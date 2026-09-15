"""
collectors/tls.py — Négociation TLS réelle via la stdlib (ssl + socket),
pas de dépendance supplémentaire nécessaire.

Produit un checks.tls.TLSEvidence — la traduction en ControlResult reste
dans checks/tls.py (interprétation pure, déjà écrite et testée).

NON EXÉCUTÉ dans ce sandbox (pas de réseau sortant). Code relu
manuellement — à vérifier via le smoke test après déploiement.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from checks.tls import TLSEvidence
from collectors._hard_timeout import HardTimeoutExceeded, run_with_hard_timeout

DEFAULT_TLS_TIMEOUT = 8.0
DEFAULT_HTTPS_PORT = 443


def _parse_cert_expiry(cert: dict) -> tuple[bool, int]:
    not_after = cert.get("notAfter")
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_remaining = (expiry - now).days
    return days_remaining < 0, days_remaining


def collect_tls_evidence(hostname: str, port: int = DEFAULT_HTTPS_PORT) -> TLSEvidence:
    """Point d'entrée public. Enveloppe `_collect_tls_evidence_impl` dans un
    timeout dur par thread — même filet de sécurité que collectors/http.py,
    pour la même raison réelle constatée : `ssl.SSLSocket.do_handshake()`
    peut bloquer indéfiniment face à un serveur qui traîne la négociation
    TLS, sans que `socket.settimeout()` ne le rattrape de façon fiable dans
    tous les cas observés en pratique."""
    hard_timeout = DEFAULT_TLS_TIMEOUT + 5.0
    try:
        return run_with_hard_timeout(_collect_tls_evidence_impl, hard_timeout, hostname, port)
    except HardTimeoutExceeded:
        # Timeout dur déclenché : ambigu par construction (on ne sait pas
        # si c'est un blocage réseau ou une négociation pathologique) ->
        # NOT_TESTABLE, jamais une anomalie critique constatée (mission §15).
        return TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=False)


def _collect_tls_evidence_impl(hostname: str, port: int) -> TLSEvidence:
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=DEFAULT_TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                negotiated_protocol = tls_sock.version()  # ex: "TLSv1.3"

                expired, days_remaining = _parse_cert_expiry(cert) if cert else (None, None)

                # Vérifie si TLS1.3 est proposé par le serveur indépendamment
                # du protocole effectivement négocié par ce client (best-effort
                # : un client Python récent négocie déjà la version la plus
                # haute disponible, donc "négocié == TLSv1.3" est en pratique
                # le signal le plus fiable disponible sans négociation manuelle
                # protocole par protocole).
                tls13_available = negotiated_protocol == "TLSv1.3"

                return TLSEvidence(
                    connection_succeeded=True,
                    certificate_expired=expired,
                    days_until_expiry=days_remaining,
                    negotiated_protocol=negotiated_protocol,
                    tls13_available=tls13_available,
                    hostname_matches=True,  # wrap_socket lève déjà si mismatch (cf. except ci-dessous)
                    is_self_signed=False,  # create_default_context() lève déjà si non fiable (cf. except)
                )

    except ssl.SSLCertVerificationError as exc:
        reason = str(exc).lower()
        if "hostname mismatch" in reason:
            return TLSEvidence(connection_succeeded=True, hostname_matches=False)
        if "self signed" in reason or "self-signed" in reason:
            return TLSEvidence(connection_succeeded=True, is_self_signed=True)
        # Autre échec de vérification (chaîne invalide, expirée détectée par
        # OpenSSL avant même le peercert Python) : anomalie critique constatée,
        # pas une absence de preuve.
        return TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=True)

    except ssl.SSLError:
        # Négociation explicitement refusée (ex: pas de protocole commun,
        # serveur n'accepte que SSLv3/TLS1.0 que ce client refuse).
        return TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=True)

    except ConnectionRefusedError:
        # Port 443 fermé : signal déterministe qu'AUCUN service TLS n'écoute
        # sur ce domaine. Ce n'est pas un aléa réseau conjoncturel (contrairement
        # à un timeout) — c'est un fait constaté équivalent à un refus de
        # négociation, donc anomalie critique (SPEC.md §8.6), pas NOT_TESTABLE.
        return TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=True)

    except (socket.timeout, TimeoutError, socket.gaierror, OSError):
        # Échec réseau ambigu (timeout, DNS, firewall silencieux...) :
        # NOT_TESTABLE, jamais une anomalie critique constatée (mission §15).
        return TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=False)
