"""
collectors/_hard_timeout.py — Filet de sécurité de dernier recours.

Contexte (bug réel observé en production, pas une hypothèse) : un audit sur
un site réel s'est bloqué indéfiniment dans `ssl.SSLSocket.do_handshake()`,
au milieu d'une poignée de main TLS — httpx/httpcore n'a pas déclenché son
propre timeout de connexion dans ce cas précis (cible ou WAF qui accepte la
connexion TCP puis ne termine jamais la négociation TLS, un motif classique
de défense anti-scanner). Le timeout "par opération" de httpx/ssl ne suffit
pas : il faut une limite de durée TOTALE, appliquée depuis l'extérieur de la
pile réseau, qui ne dépend d'aucun mécanisme interne à httpx/ssl/socket.

Principe : exécuter l'appel réseau dans un thread séparé et n'attendre son
résultat qu'un temps borné. Si le thread ne revient pas à temps, on
abandonne — le thread sous-jacent peut continuer à vivre en arrière-plan
(Python ne permet pas de tuer un thread de force), mais il ne bloque plus
l'audit. C'est un compromis assumé : mieux vaut un thread orphelin qui finit
par expirer tout seul (ou vit jusqu'à la fin du process) qu'un audit qui ne
se termine jamais.
"""

from __future__ import annotations

import concurrent.futures
from typing import Callable, TypeVar

T = TypeVar("T")

# Pool partagé, taille bornée : un audit synchrone ne lance jamais plus de
# quelques opérations réseau "en vol" à la fois (elles sont séquentielles
# par construction dans audit_service.py), donc un pool restreint suffit
# et évite d'accumuler des threads bloqués sans limite en cas de cible
# systématiquement pathologique.
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="websec-net")


class HardTimeoutExceeded(Exception):
    """Levée quand une opération réseau dépasse son délai dur, quelle que
    soit la raison sous-jacente (handshake TLS bloqué, DNS qui ne répond
    jamais, etc.). Traduite par l'appelant en résultat NOT_TESTABLE/erreur
    réseau — jamais en résultat défavorable (mission §3/§15)."""


def run_with_hard_timeout(fn: Callable[..., T], hard_timeout_seconds: float, *args, **kwargs) -> T:
    future = _EXECUTOR.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=hard_timeout_seconds)
    except concurrent.futures.TimeoutError as exc:
        raise HardTimeoutExceeded(
            f"Opération réseau non terminée après {hard_timeout_seconds:.0f}s (timeout dur)."
        ) from exc
