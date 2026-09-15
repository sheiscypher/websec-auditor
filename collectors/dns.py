"""
collectors/dns.py — Résolution DNS réelle (DNSSEC, MX, SPF, DMARC).

Utilise dnspython. Comme collectors/http.py, ce module produit de
l'evidence brute — aucune interprétation ici (voir checks/dns_security.py
et checks/email_security.py pour la traduction en ControlResult).

NON EXÉCUTÉ dans ce sandbox (pas de réseau/DNS sortant disponible). Code
relu manuellement — à vérifier en premier via le smoke test après
déploiement.
"""

from __future__ import annotations

import dns.resolver
import dns.exception

from collectors._hard_timeout import HardTimeoutExceeded, run_with_hard_timeout

DEFAULT_DNS_TIMEOUT = 5.0
_HARD_TIMEOUT = DEFAULT_DNS_TIMEOUT + 5.0


def check_dnssec(domain: str) -> bool | None:
    """True/False si la résolution a abouti, None si elle a échoué
    (NOT_TESTABLE côté check, jamais interprété ici). Timeout dur en plus
    du timeout dnspython — même filet de sécurité que http.py/tls.py."""
    try:
        return run_with_hard_timeout(_check_dnssec_impl, _HARD_TIMEOUT, domain)
    except HardTimeoutExceeded:
        return None


def _check_dnssec_impl(domain: str) -> bool | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_DNS_TIMEOUT
        resolver.lifetime = DEFAULT_DNS_TIMEOUT
        answer = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        return answer.rrset is not None
    except dns.exception.DNSException:
        return None


def has_mx_record(domain: str) -> bool | None:
    try:
        return run_with_hard_timeout(_has_mx_record_impl, _HARD_TIMEOUT, domain)
    except HardTimeoutExceeded:
        return None


def _has_mx_record_impl(domain: str) -> bool | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_DNS_TIMEOUT
        resolver.lifetime = DEFAULT_DNS_TIMEOUT
        answer = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        return answer.rrset is not None and len(answer.rrset) > 0
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.DNSException:
        return None


def get_spf_record(domain: str) -> str | None:
    try:
        return run_with_hard_timeout(_get_spf_record_impl, _HARD_TIMEOUT, domain)
    except HardTimeoutExceeded:
        return None


def _get_spf_record_impl(domain: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_DNS_TIMEOUT
        resolver.lifetime = DEFAULT_DNS_TIMEOUT
        answer = resolver.resolve(domain, "TXT", raise_on_no_answer=False)
        if answer.rrset is None:
            return None
        for rdata in answer.rrset:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.lower().startswith("v=spf1"):
                return txt
        return None
    except dns.exception.DNSException:
        return None


def get_dmarc_record(domain: str) -> tuple[bool, str | None]:
    """Retourne (present, policy). policy is None si absent ou non parsable."""
    try:
        return run_with_hard_timeout(_get_dmarc_record_impl, _HARD_TIMEOUT, domain)
    except HardTimeoutExceeded:
        return False, None


def _get_dmarc_record_impl(domain: str) -> tuple[bool, str | None]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_DNS_TIMEOUT
        resolver.lifetime = DEFAULT_DNS_TIMEOUT
        answer = resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
        if answer.rrset is None:
            return False, None
        for rdata in answer.rrset:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.lower().startswith("v=dmarc1"):
                policy = None
                for part in txt.split(";"):
                    part = part.strip().lower()
                    if part.startswith("p="):
                        policy = part.split("=", 1)[1]
                return True, policy
        return False, None
    except dns.exception.DNSException:
        return False, None
