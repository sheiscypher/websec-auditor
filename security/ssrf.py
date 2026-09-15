"""
security/ssrf.py — Validation d'URL et protection SSRF (mission complément §7).

Séparation délibérée en deux étages, pour rester testable sans réseau :

1. `parse_and_validate_scheme(url)` — validation SYNTAXIQUE pure (schéma,
   présence d'un hostname). Aucune I/O.
2. `resolve_hostname(hostname)` — résolution DNS réelle (I/O réseau,
   non testable de façon déterministe ici).
3. `is_ip_blocked(ip)` — logique pure de classification d'une IP résolue.
4. `validate_resolved_ips(ips)` — combine 3 sur une liste d'IPs, pure.

`ensure_url_is_safe(url)` orchestre les deux étages pour un usage réel.

LIMITE DOCUMENTÉE (à ne pas cacher) : entre la résolution DNS de validation
et la requête HTTP réelle effectuée par les collectors, un attaquant
contrôlant le DNS de la cible pourrait changer la résolution (DNS
rebinding) et contourner ce contrôle. Une mitigation complète nécessite un
transport HTTP à IP épinglée (connecter directement à l'IP validée, avec le
Host header d'origine) — jugé disproportionné pour une V1 portfolio et non
implémenté ici. Ce risque résiduel est documenté dans le README et dans le
threat model, pas masqué.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

# IPv4 : RFC 1918 (privé), loopback, link-local (incl. métadonnées cloud
# 169.254.169.254), multicast, réservé. IPv6 équivalents.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),    # multicast
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),       # ULA
    ipaddress.ip_network("fe80::/10"),      # link-local v6
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6 (rejoue les ranges v4 ci-dessus)
]

MAX_REDIRECTS = 5


class URLValidationError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ParsedTarget:
    scheme: str
    hostname: str
    port: int | None
    original_url: str


def parse_and_validate_scheme(url: str) -> ParsedTarget:
    """Validation syntaxique pure — aucune I/O réseau."""
    if not url or not isinstance(url, str):
        raise URLValidationError("URL vide ou invalide.")

    parsed = urlparse(url.strip())

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Schéma non autorisé : '{parsed.scheme or '(absent)'}'. "
            f"Seuls http/https sont acceptés."
        )

    if not parsed.hostname:
        raise URLValidationError("Aucun nom d'hôte détecté dans l'URL.")

    # Rejet explicite des littéraux IP privés écrits directement en clair
    # (avant même toute résolution DNS).
    try:
        literal_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None and is_ip_blocked(literal_ip):
        raise URLValidationError(f"Adresse IP non autorisée : {literal_ip}.")

    return ParsedTarget(
        scheme=parsed.scheme.lower(),
        hostname=parsed.hostname,
        port=parsed.port,
        original_url=url.strip(),
    )


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Logique pure, testable sans réseau."""
    return any(ip in network for network in BLOCKED_NETWORKS)


def validate_resolved_ips(ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> None:
    if not ips:
        raise URLValidationError("Résolution DNS n'a retourné aucune adresse IP.")
    for ip in ips:
        if is_ip_blocked(ip):
            raise URLValidationError(f"Résolution vers une adresse IP non autorisée : {ip}.")


def resolve_hostname(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """I/O réseau réelle — non couverte par les tests unitaires déterministes
    (dépend de la disponibilité DNS de l'environnement d'exécution)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise URLValidationError(f"Résolution DNS impossible pour '{hostname}': {exc}") from exc

    ips = []
    for info in infos:
        raw_ip = info[4][0]
        try:
            ips.append(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
    return ips


def ensure_url_is_safe(url: str) -> ParsedTarget:
    """Point d'entrée unique pour les collectors : valide syntaxe + DNS.
    Lève URLValidationError si l'URL doit être rejetée avant tout audit."""
    target = parse_and_validate_scheme(url)
    ips = resolve_hostname(target.hostname)
    validate_resolved_ips(ips)
    return target


def validate_redirect_target(location: str) -> ParsedTarget:
    """À appeler pour CHAQUE redirection HTTP rencontrée par un collector —
    ne jamais suivre une redirection sans revalider (protection open
    redirect vers une cible interne)."""
    return ensure_url_is_safe(location)
