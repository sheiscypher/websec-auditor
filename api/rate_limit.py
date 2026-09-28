"""
api/rate_limit.py — Protection anti-abus du endpoint /audit.

Indépendant du throttle déjà existant côté cible (collectors/http.py,
1 req/s par domaine audité) : celui-là protège LE SITE AUDITÉ. Celui-ci
protège NOTRE service lui-même contre un appelant qui spammerait /audit —
gap identifié après coup, pas couvert par la conception initiale.

Deux mécanismes complémentaires, en mémoire, sans dépendance externe
(cohérent avec le choix déjà fait pour le throttle par domaine dans
collectors/http.py — même pattern dict + lock) :

1. Limite par IP appelante (fenêtre glissante) : évite qu'une seule
   source sature le service en boucle.
2. Limite de concurrence globale (sémaphore) : protège la capacité totale
   du serveur même face à des appels distribués sur des IP différentes —
   un audit prend jusqu'à 90s et sollicite un pool de threads PARTAGÉ
   (collectors/_hard_timeout.py, 4 workers), donc même sans dépasser la
   limite par IP, un nombre suffisant d'appelants distincts pourrait
   saturer ce pool.
"""

from __future__ import annotations

import ipaddress
import threading
import time

MAX_REQUESTS_PER_WINDOW = 5
WINDOW_SECONDS = 300.0  # 5 minutes
MAX_CONCURRENT_AUDITS = 3
# Borne mémoire : nombre maximal d'adresses suivies simultanément. Au-delà, les
# entrées expirées sont purgées ; si le service reste saturé, il refuse plutôt
# que de grossir sans limite.
MAX_TRACKED_IPS = 10_000

_request_log: dict[str, list[float]] = {}
_log_lock = threading.Lock()

_concurrency_semaphore = threading.Semaphore(MAX_CONCURRENT_AUDITS)


class RateLimitExceeded(Exception):
    """Levée quand l'appelant dépasse la limite de requêtes par IP sur la fenêtre glissante."""


DEFAULT_TRUSTED_PROXY_HOPS = 1


def select_client_ip(forwarded_for: str | None, peer_host: str | None, trusted_hops: int = DEFAULT_TRUSTED_PROXY_HOPS) -> str:
    """Adresse de l'appelant, sans se fier à ce qu'il déclare lui-même.

    Chaque proxy de confiance AJOUTE à droite de X-Forwarded-For l'adresse
    dont il a reçu la requête ; tout ce qui se trouve à gauche peut être
    fabriqué par l'appelant. On lit donc depuis la droite :
    `trusted_hops` = nombre de proxys de confiance devant l'application,
    l'appelant réel étant la N-ième entrée en partant de la fin.

    Repli sur l'adresse de la connexion (`peer_host`) si l'en-tête est
    absent, plus court que prévu, ou si la valeur n'est pas une adresse IP
    valide. Ce repli est sûr (non falsifiable) mais moins précis : derrière
    un proxy, tous les appelants partagent alors la même clé.

    Ne jamais SURESTIMER `trusted_hops` : on lirait une entrée située à
    gauche des proxys, donc falsifiable. Voir README/api/main.py pour la
    calibration.
    """
    fallback = peer_host or "unknown"
    if trusted_hops < 1 or not forwarded_for:
        return fallback
    entries = [e.strip() for e in forwarded_for.split(",") if e.strip()]
    if len(entries) < trusted_hops:
        return fallback
    try:
        return str(ipaddress.ip_address(entries[-trusted_hops]))
    except ValueError:
        return fallback


def _purge_expired(cutoff: float) -> None:
    """Retire les adresses dont la dernière requête est sortie de la
    fenêtre. À appeler sous _log_lock."""
    for ip in [ip for ip, ts in _request_log.items() if not ts or ts[-1] < cutoff]:
        del _request_log[ip]


def check_and_register_request(client_ip: str, now: float | None = None) -> None:
    """Lève RateLimitExceeded si `client_ip` a déjà atteint
    MAX_REQUESTS_PER_WINDOW requêtes dans les WINDOW_SECONDS dernières
    secondes. Enregistre la requête courante sinon (fenêtre glissante,
    purge des entrées expirées à chaque appel — pas de tâche de nettoyage
    séparée à maintenir).

    `now` injectable pour les tests déterministes (sinon time.monotonic())."""
    current_time = now if now is not None else time.monotonic()
    cutoff = current_time - WINDOW_SECONDS
    with _log_lock:
        if client_ip not in _request_log and len(_request_log) >= MAX_TRACKED_IPS:
            _purge_expired(cutoff)
            if len(_request_log) >= MAX_TRACKED_IPS:
                raise RateLimitExceeded("Service temporairement saturé. Réessayez plus tard.")
        timestamps = _request_log.get(client_ip, [])
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
        if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
            _request_log[client_ip] = timestamps
            raise RateLimitExceeded(
                f"Trop de requêtes depuis cette adresse ({MAX_REQUESTS_PER_WINDOW} maximum "
                f"par {int(WINDOW_SECONDS)}s). Réessayez plus tard."
            )
        timestamps.append(current_time)
        _request_log[client_ip] = timestamps


def try_acquire_audit_slot() -> bool:
    """Tente d'acquérir un slot de concurrence, sans attendre (retourne
    immédiatement False si MAX_CONCURRENT_AUDITS est déjà atteint) — on
    préfère refuser proprement (429) plutôt que mettre en file d'attente
    indéfiniment un appelant, ce qui masquerait le vrai signal de charge."""
    return _concurrency_semaphore.acquire(blocking=False)


def release_audit_slot() -> None:
    _concurrency_semaphore.release()
