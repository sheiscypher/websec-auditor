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

import threading
import time
from collections import defaultdict

MAX_REQUESTS_PER_WINDOW = 5
WINDOW_SECONDS = 300.0  # 5 minutes
MAX_CONCURRENT_AUDITS = 3

_request_log: dict[str, list[float]] = defaultdict(list)
_log_lock = threading.Lock()

_concurrency_semaphore = threading.Semaphore(MAX_CONCURRENT_AUDITS)


class RateLimitExceeded(Exception):
    """Levée quand l'appelant dépasse la limite de requêtes par IP sur la fenêtre glissante."""


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
        timestamps = _request_log[client_ip]
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
        if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
            raise RateLimitExceeded(
                f"Trop de requêtes depuis cette adresse ({MAX_REQUESTS_PER_WINDOW} maximum "
                f"par {int(WINDOW_SECONDS)}s). Réessayez plus tard."
            )
        timestamps.append(current_time)


def try_acquire_audit_slot() -> bool:
    """Tente d'acquérir un slot de concurrence, sans attendre (retourne
    immédiatement False si MAX_CONCURRENT_AUDITS est déjà atteint) — on
    préfère refuser proprement (429) plutôt que mettre en file d'attente
    indéfiniment un appelant, ce qui masquerait le vrai signal de charge."""
    return _concurrency_semaphore.acquire(blocking=False)


def release_audit_slot() -> None:
    _concurrency_semaphore.release()
