"""
collectors/http.py — Collecte HTTP réelle. Aucune interprétation ici (les
checks/*.py restent purs) : ce module produit de l'evidence brute.

Sécurité (mission complément §7) :
- SSRF : chaque requête passe par security.ssrf.ensure_url_is_safe(), et
  chaque redirection est revalidée individuellement (follow_redirects
  désactivé, boucle manuelle bornée à MAX_REDIRECTS).
- Timeout réseau appliqué à chaque requête.
- Taille de réponse plafonnée (MAX_RESPONSE_BYTES) pour éviter
  l'épuisement mémoire sur une cible malveillante ou un fichier volumineux.
- User-Agent déclaré et identifiable (transparence, cf. ancien ADR conservé).

NON EXÉCUTÉ EN CI/CD DANS CE SANDBOX : nécessite httpx installé et un accès
réseau sortant, indisponibles dans l'environnement d'implémentation. Code
relu manuellement, pas testé en conditions réelles à ce stade — à vérifier
en premier après déploiement (cf. smoke test).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import httpx

from collectors._hard_timeout import HardTimeoutExceeded, run_with_hard_timeout
from security.ssrf import URLValidationError, ensure_url_is_safe, validate_redirect_target

DEFAULT_TIMEOUT_SECONDS = 8.0
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 Mo — suffisant pour HTML/JS/robots/sitemap
USER_AGENT = "WebSecAuditor/1.0 (+https://github.com/sheiscypher/websec-auditor)"

# Rate limiting par domaine — mentionné dès la conception initiale ("outil
# non intrusif") comme une exigence à conserver de l'ancien outil, mais
# jamais implémenté avant ce correctif. Conséquence réelle observée :
# ~20-25 requêtes tirées en rafale vers le même domaine dans un audit
# ressemblent exactement au profil qu'un WAF/anti-scanner pénalise
# (ralentissement délibéré, voire blocage). 1 req/s par domaine, cohérent
# avec la valeur documentée dès l'origine du projet.
MIN_INTERVAL_PER_HOST_SECONDS = 1.0
_last_request_time_by_host: dict[str, float] = {}
_throttle_lock = threading.Lock()


def _throttle_for_host(hostname: str) -> None:
    with _throttle_lock:
        now = time.monotonic()
        last = _last_request_time_by_host.get(hostname)
        if last is not None:
            wait = MIN_INTERVAL_PER_HOST_SECONDS - (now - last)
            if wait > 0:
                time.sleep(wait)
        _last_request_time_by_host[hostname] = time.monotonic()


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int | None
    headers: dict[str, str] | None
    body: str
    content_type: str | None
    truncated: bool = False
    error: str | None = None
    set_cookie_headers: tuple[str, ...] = field(default_factory=tuple)


def _headers_to_dict(headers: httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items()}


def safe_get(url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> FetchResult:
    """Point d'entrée public. Enveloppe `_safe_get_impl` dans un timeout dur
    par thread (collectors/_hard_timeout.py) — filet de sécurité de dernier
    recours quand httpx/ssl ne déclenchent pas leur propre timeout (cas réel
    observé : poignée de main TLS bloquée indéfiniment, cf. compte rendu).
    Ne lève jamais d'exception vers l'appelant : toute anomalie devient un
    FetchResult.error (mission §15)."""
    # Timeout dur volontairement proche de `timeout` (pas multiplié par
    # MAX_REDIRECTS) : on préfère couper court sur un hop de redirection
    # pathologique plutôt que risquer qu'un seul appel dépasse à lui seul
    # le budget de temps global de l'audit (services/audit_service.py).
    # Un site normal ne rencontre presque jamais plus d'1-2 redirections ;
    # accepter de sacrifier un cas extrême de chaîne de redirections toutes
    # lentes est un compromis déterminisme > exhaustivité, assumé.
    hard_timeout = timeout + 5.0
    try:
        return run_with_hard_timeout(_safe_get_impl, hard_timeout, url, timeout)
    except HardTimeoutExceeded:
        return FetchResult(
            url=url, status_code=None, headers=None, body="", content_type=None,
            error="TIMEOUT_HARD",
        )


def _safe_get_impl(url: str, timeout: float) -> FetchResult:
    """Effectue un GET en validant l'URL, chaque redirection, et en
    plafonnant la taille lue. Ne lève jamais d'exception réseau vers
    l'appelant : les erreurs sont encodées dans FetchResult.error (cf.
    mission §15 — une erreur technique n'est pas un FAIL de sécurité, elle
    doit être distinguée explicitement pour que les checks la traduisent
    en NOT_TESTABLE, jamais en ABSENT/FAIL implicite)."""

    current_url = url
    redirects_followed = 0
    # Délai GLOBAL montre en main pour toute la requête (y compris
    # redirections et lecture du corps), en plus du timeout httpx par
    # opération. httpx applique son timeout par opération de lecture, pas
    # sur la durée totale — un serveur qui répond lentement par petits
    # paquets (ou un WAF qui "tarpit" un scanner détecté) peut ainsi
    # dépasser très largement `timeout` sans jamais déclencher
    # httpx.TimeoutException. C'est un vrai cas observé en usage réel
    # (audit de production ayant semblé "bloqué"), corrigé ici.
    deadline = time.monotonic() + timeout

    try:
        ensure_url_is_safe(current_url)
    except URLValidationError as exc:
        return FetchResult(url=url, status_code=None, headers=None, body="", content_type=None, error=str(exc))

    with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
        while True:
            if time.monotonic() > deadline:
                return FetchResult(
                    url=current_url, status_code=None, headers=None, body="", content_type=None,
                    error="TIMEOUT_GLOBAL",
                )
            _throttle_for_host(httpx.URL(current_url).host)
            try:
                with client.stream("GET", current_url) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        redirects_followed += 1
                        if not location or redirects_followed > MAX_REDIRECTS:
                            return FetchResult(
                                url=current_url,
                                status_code=response.status_code,
                                headers=_headers_to_dict(response.headers),
                                body="",
                                content_type=response.headers.get("content-type"),
                                error="Trop de redirections ou redirection sans Location.",
                            )
                        try:
                            validate_redirect_target(location)
                        except URLValidationError as exc:
                            return FetchResult(
                                url=current_url,
                                status_code=response.status_code,
                                headers=_headers_to_dict(response.headers),
                                body="",
                                content_type=None,
                                error=f"Redirection bloquée : {exc}",
                            )
                        current_url = location
                        continue

                    content_type = response.headers.get("content-type")
                    headers_dict = _headers_to_dict(response.headers)
                    status_code = response.status_code
                    set_cookie_headers = tuple(response.headers.get_list("set-cookie"))

                    body_bytes = bytearray()
                    truncated = False
                    for chunk in response.iter_bytes():
                        body_bytes.extend(chunk)
                        if len(body_bytes) > MAX_RESPONSE_BYTES:
                            truncated = True
                            break
                        if time.monotonic() > deadline:
                            # Lecture en cours mais trop lente cumulativement
                            # (ex: drip-feed) : on coupe et on renvoie ce qui
                            # a été lu, marqué tronqué plutôt que de bloquer
                            # indéfiniment.
                            truncated = True
                            break

                    try:
                        body_text = body_bytes.decode(response.encoding or "utf-8", errors="replace")
                    except (LookupError, TypeError):
                        body_text = body_bytes.decode("utf-8", errors="replace")

                    return FetchResult(
                        url=current_url,
                        status_code=status_code,
                        headers=headers_dict,
                        body=body_text,
                        content_type=content_type,
                        truncated=truncated,
                        set_cookie_headers=set_cookie_headers,
                    )
            except httpx.TimeoutException:
                return FetchResult(
                    url=current_url, status_code=None, headers=None, body="", content_type=None,
                    error="TIMEOUT",
                )
            except httpx.RequestError as exc:
                return FetchResult(
                    url=current_url, status_code=None, headers=None, body="", content_type=None,
                    error=f"CONNECTION_ERROR: {exc}",
                )


def safe_head(url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> FetchResult:
    """Utilisé pour les sondes de chemins sensibles (sec.exposed_files) —
    HEAD d'abord, GET seulement si nécessaire pour confirmer le contenu
    (cf. checks/exposure.py, qui a besoin d'un extrait de corps pour son
    filtre anti-faux-positif : ce collector reste donc un GET plafonné en
    pratique, HEAD seul étant insuffisant pour le filtrage par mots-clés)."""
    return safe_get(url, timeout=timeout)


def fetch_external_resources(html: str, base_url: str) -> list[tuple[str, bool]]:
    """Extrait les ressources <script src> / <link href> pointant vers un
    domaine tiers, avec présence ou non de l'attribut SRI. Analyse HTML
    simple par expressions régulières (pas de dépendance BeautifulSoup
    supplémentaire pour ce collector — décision de simplicité, cf. mission
    complément §1 'ne pas sur-architecturer')."""
    import re
    from urllib.parse import urlparse

    base_host = urlparse(base_url).hostname

    resources: list[tuple[str, bool]] = []
    tag_pattern = re.compile(r"<(script|link)\b[^>]*>", re.IGNORECASE)
    src_pattern = re.compile(r'(?:src|href)=["\']([^"\']+)["\']', re.IGNORECASE)
    integrity_pattern = re.compile(r'integrity=["\'][^"\']+["\']', re.IGNORECASE)

    for tag_match in tag_pattern.finditer(html):
        tag = tag_match.group(0)
        src_match = src_pattern.search(tag)
        if not src_match:
            continue
        src = src_match.group(1)
        if not src.startswith(("http://", "https://", "//")):
            continue  # ressource locale, pas un tiers
        host = urlparse(src if "://" in src else f"https:{src}").hostname
        if host and host != base_host:
            has_sri = bool(integrity_pattern.search(tag))
            resources.append((src, has_sri))

    return resources
