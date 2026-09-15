"""
services/audit_service.py — Orchestrateur de l'audit (mission complément §5/§6).

C'est la SEULE couche qui connaît à la fois les collectors, les checks et
le catalogue. Elle ne contient elle-même aucune logique de détection
(déléguée aux checks/*.py) ni aucune logique de scoring (déléguée à
scoring.py) — uniquement la connexion des trois.

NON EXÉCUTÉ EN CONDITIONS RÉELLES dans ce sandbox : dépend de httpx,
dnspython et d'un accès réseau sortant, indisponibles ici. Relu
manuellement. Un test d'intégration avec collectors mockés est fourni
(tests/test_audit_service.py) pour vérifier le câblage Evidence→Score
indépendamment du réseau réel.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

from checks import ai_signals, cms, cookies, dns_security, email_security, exposure, headers, privacy, secrets, security_txt, supply_chain, tls
from collectors import dns as dns_collector
from collectors import http as http_collector
from collectors import tls as tls_collector
from collectors.html_parse import extract_anchor_links, href_path_matches, link_text_matches
from config.ai_signal_paths import (
    AI_USAGE_MENTION_KEYWORDS,
    BOT_USER_AGENTS_OF_INTEREST,
    CHATBOT_SCRIPT_MARKERS,
    GOVERNANCE_DOC_PATHS,
)
from config.exposed_paths import SENSITIVE_PATHS
from config.legal_pages_paths import (
    LEGAL_NOTICE_HREF_KEYWORDS,
    LEGAL_NOTICE_LINK_TEXT_MARKERS,
    LEGAL_NOTICE_PATHS,
    PRIVACY_POLICY_HREF_KEYWORDS,
    PRIVACY_POLICY_LINK_TEXT_MARKERS,
    PRIVACY_POLICY_PATHS,
)
from config.tracker_domains import categorize_tracker_domain
from control_catalog import CATALOG_BY_ID, FULL_CATALOG
from enums import AxisStatus, ControlResult, Domain, ScoringStatus
from results import CheckOutcome, build_finding
from scoring import compute_ai_governance_panel, compute_axis_score, grade_from_score, signal_level_from_score
from security.ssrf import URLValidationError, ensure_url_is_safe

# Budget de temps global pour l'ensemble de l'audit (mission complément §8 :
# "limiter raisonnablement les réponses" — appliqué ici à la durée totale,
# pas seulement à la taille). Valeur relevée de 45s à 90s suite à
# l'introduction du rate limiting par domaine (1 req/s, cf.
# collectors/http.py) : avec ~20-25 sondes séquentielles vers le même
# domaine, le seul temps de respect du throttle représente déjà ~20-25s
# incompressibles avant même de compter la latence réseau réelle. 90s
# reste borné et documenté — pas un budget "au cas où" laissé sans limite.
AUDIT_TIME_BUDGET_SECONDS = 90.0


class AuditTimeBudget:
    """Suivi du temps écoulé pour tout l'audit. Quand le budget est dépassé,
    les blocs de contrôles restants ne lancent plus AUCUNE requête réseau et
    basculent en NOT_TESTABLE — jamais en ABSENT/FAIL implicite (mission §3 :
    un dépassement de temps n'est pas une preuve d'absence)."""

    def __init__(self, budget_seconds: float = AUDIT_TIME_BUDGET_SECONDS):
        self._deadline = time.monotonic() + budget_seconds

    @property
    def expired(self) -> bool:
        return time.monotonic() > self._deadline


def _budget_exceeded_outcome(control_id: str) -> CheckOutcome:
    return CheckOutcome(
        control_id=control_id,
        result=ControlResult.NOT_TESTABLE,
        evidence="Budget de temps global de l'audit dépassé avant l'exécution de ce contrôle.",
        detection_method="N/A — contrôle non exécuté (budget de temps).",
    )


class AuditInputError(Exception):
    """Levée quand l'URL fournie est invalide ou bloquée (SSRF). L'appelant
    (api/main.py) la traduit en HTTP 400 — jamais en erreur 500 générique."""


# ---------------------------------------------------------------------------
# Heuristiques de collecte "best-effort" propres à l'orchestrateur (pas des
# checks : ce sont des approximations de préparation d'evidence, documentées
# comme telles, jamais des décisions de scoring).
# ---------------------------------------------------------------------------

SPA_SHELL_MARKERS: tuple[str, ...] = (
    'id="root"',
    "id='root'",
    'id="app"',
    "id='app'",
    'id="__next"',
    "id='__next'",
    "data-reactroot",
    "ng-version",
    "__nuxt__",
    "window.__initial_state__",
)


def _looks_like_client_side_only(html: str) -> bool:
    """Heuristique V1 corrigée après le smoke test réel sur example.com
    (voir compte rendu) : un texte court NE SUFFIT PAS à conclure à une
    SPA — une page statique légitimement minimaliste (ex: example.com,
    ~25 mots de texte visible) produisait un faux positif systématique,
    masquant un ABSENT honnête derrière un NOT_TESTABLE non mérité.

    Le critère exige désormais la CONJONCTION de deux signaux : peu de
    texte visible ET un marqueur technique réel d'application JS (id de
    shell connu, attribut de framework). Un texte court sans marqueur SPA
    reste traité comme une page statique normale, donc concluante."""
    text_only = re.sub(r"<[^>]+>", " ", html)
    words = [w for w in text_only.split() if w.strip()]
    has_spa_marker = any(marker in html.lower() for marker in SPA_SHELL_MARKERS)
    return len(words) < 40 and has_spa_marker


def _extract_script_srcs(html: str) -> tuple[str, ...]:
    return tuple(re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Orchestration par domaine
# ---------------------------------------------------------------------------

def _run_security_checks(base_url: str, hostname: str, homepage, budget: AuditTimeBudget) -> dict[str, CheckOutcome]:
    outcomes: dict[str, CheckOutcome] = {}

    outcomes[headers.CONTROL_ID] = headers.evaluate_headers(
        homepage.headers if homepage.error is None else None
    )

    if budget.expired:
        outcomes[tls.CONTROL_ID] = _budget_exceeded_outcome(tls.CONTROL_ID)
    else:
        tls_evidence = tls_collector.collect_tls_evidence(hostname)
        outcomes[tls.CONTROL_ID] = tls.evaluate_tls(tls_evidence)

    if budget.expired:
        outcomes[exposure.CONTROL_ID] = _budget_exceeded_outcome(exposure.CONTROL_ID)
    else:
        probes = []
        for path in SENSITIVE_PATHS:
            if budget.expired:
                break
            result = http_collector.safe_get(base_url.rstrip("/") + path)
            probes.append(
                exposure.PathProbeResult(
                    path=path,
                    http_status=result.status_code,
                    content_type=result.content_type,
                    body_snippet=result.body[:2000],
                )
            )
        # Si le budget a coupé la boucle avant d'avoir testé AUCUN chemin,
        # `probes` est vide -> evaluate_exposed_files renvoie déjà
        # NOT_TESTABLE ("Aucune requête n'a pu être exécutée"), cohérent.
        # Si une partie a pu être testée, le résultat porte sur ce qui a
        # réellement été observé — jamais présenté comme une couverture
        # complète (le libellé du contrôle reste factuel par construction).
        outcomes[exposure.CONTROL_ID] = exposure.evaluate_exposed_files(probes)

    scanned_resources = None
    if homepage.error is None:
        scanned_resources = [secrets.ScannedResource(path=base_url, content=homepage.body)]
    outcomes[secrets.CONTROL_ID_PATTERN] = secrets.evaluate_secret_patterns(scanned_resources)
    corroborated = secrets.evaluate_corroborated_signal(scanned_resources)
    if corroborated is not None:
        outcomes[secrets.CONTROL_ID_CORROBORATED] = corroborated

    if budget.expired:
        outcomes[dns_security.CONTROL_ID] = _budget_exceeded_outcome(dns_security.CONTROL_ID)
        outcomes[email_security.CONTROL_ID] = _budget_exceeded_outcome(email_security.CONTROL_ID)
    else:
        outcomes[dns_security.CONTROL_ID] = dns_security.evaluate_dnssec(
            dns_collector.check_dnssec(hostname)
        )

        has_mx = dns_collector.has_mx_record(hostname)
        email_evidence = email_security.EmailSecurityEvidence(has_mx_record=has_mx)
        if has_mx:
            spf = dns_collector.get_spf_record(hostname)
            dmarc_present, dmarc_policy = dns_collector.get_dmarc_record(hostname)
            email_evidence = email_security.EmailSecurityEvidence(
                has_mx_record=True,
                spf_present=spf is not None,
                dmarc_present=dmarc_present,
                dmarc_policy=dmarc_policy,
            )
        outcomes[email_security.CONTROL_ID] = email_security.evaluate_email_security(email_evidence)

    external_resources = []
    if homepage.error is None:
        for src, has_sri in http_collector.fetch_external_resources(homepage.body, base_url):
            external_resources.append(supply_chain.ExternalResource(url=src, has_sri=has_sri))
    outcomes[supply_chain.CONTROL_ID_SRI] = supply_chain.evaluate_sri(
        external_resources if homepage.error is None else None
    )

    cms_evidence = cms.CMSDetectionEvidence(name=None)
    if homepage.error is None:
        match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', homepage.body, re.IGNORECASE)
        if match:
            cms_evidence = cms.CMSDetectionEvidence(name=match.group(1), version_confidence="low")
    outcomes[cms.CONTROL_ID_DETECTION] = cms.evaluate_cms_detection(cms_evidence)
    # sec.cms_cve_mapping : non implémenté en V1 (dépendance NVD externe
    # jugée disproportionnée pour cette version, cf. compte rendu). Aucun
    # outcome produit — le contrôle reste dans le catalogue mais ne
    # produit jamais de finding tant que ce collector n'existe pas.

    # Cookies : aucune requête réseau supplémentaire — réutilise
    # homepage.set_cookie_headers déjà collecté par le fetch initial.
    cookie_headers = homepage.set_cookie_headers if homepage.error is None else None
    outcomes[cookies.CONTROL_ID_SECURE_HTTPONLY] = cookies.evaluate_secure_httponly(cookie_headers)
    samesite_outcome = cookies.evaluate_samesite_distribution(cookie_headers)
    if samesite_outcome is not None:
        outcomes[cookies.CONTROL_ID_SAMESITE] = samesite_outcome

    # security.txt : emplacement canonique puis repli (RFC 9116), 1-2
    # requêtes réseau -> gardé par le budget global de l'audit.
    if budget.expired:
        outcomes[security_txt.CONTROL_ID] = _budget_exceeded_outcome(security_txt.CONTROL_ID)
    else:
        found_path = None
        canonical = http_collector.safe_get(base_url.rstrip("/") + security_txt.CANONICAL_PATH)
        if canonical.status_code == 200:
            found_path = security_txt.CANONICAL_PATH
        elif not budget.expired:
            fallback = http_collector.safe_get(base_url.rstrip("/") + security_txt.FALLBACK_PATH)
            if fallback.status_code == 200:
                found_path = security_txt.FALLBACK_PATH
        outcomes[security_txt.CONTROL_ID] = security_txt.evaluate_security_txt(found_path)

    return outcomes


def _run_privacy_checks(base_url: str, homepage, budget: AuditTimeBudget) -> dict[str, CheckOutcome]:
    outcomes: dict[str, CheckOutcome] = {}

    # Quatre causes distinctes rendent une conclusion ABSENT non fiable pour
    # les pages légales : heuristique SPA, sondage interrompu par le budget,
    # page tronquée par le plafond de taille (collectors/http.py,
    # MAX_RESPONSE_BYTES), OU requête bloquée/en échec sur un chemin précis
    # (403/429/503, timeout, ou réponse "200" quasi vide type soft-404).
    # Dans tous les cas, une absence non trouvée doit rester NOT_TESTABLE,
    # jamais ABSENT (mission §3/§15 : une limite technique n'est jamais une
    # preuve d'absence).
    BLOCKING_STATUS_CODES = {403, 429, 503}
    MIN_CONFIRMED_PAGE_BODY_LENGTH = 200  # garde-fou anti "200 mais page quasi vide"

    def _probe_indicates_blocking(result) -> bool:
        if result.status_code in BLOCKING_STATUS_CODES:
            return True
        if result.status_code is None and result.error:
            return True  # timeout, SSRF, erreur de connexion, etc.
        return False

    def _probe_confirms_page(result) -> bool:
        return result.status_code == 200 and len(result.body) >= MIN_CONFIRMED_PAGE_BODY_LENGTH

    detection_unreliable = (
        (_looks_like_client_side_only(homepage.body) if homepage.error is None else False)
        or (homepage.truncated if homepage.error is None else False)
    )

    # CAUSE RACINE CORRIGÉE (cf. compte rendu) : la détection reposait
    # uniquement sur (a) une liste de chemins devinés à sonder par requête
    # séparée — vulnérable au blocage WAF d'un chemin précis — et (b) une
    # recherche de sous-chaîne AVEUGLE sur tout le HTML brut, sans jamais
    # extraire de VRAIS liens (href + texte visible), sans normalisation
    # des accents, et vulnérable à la troncature de page.
    #
    # Nouvel ordre de détection, mécanisme PRIMAIRE d'abord :
    #   1. Liens réellement extraits de la page déjà récupérée (gratuit,
    #      pas de requête réseau, insensible au blocage par chemin) ;
    #   2. Sondage direct de chemins connus, en confirmant le contenu
    #      (pas juste le code 200) et en distinguant "page absente" (404)
    #      de "requête bloquée/en échec" (403/429/503/timeout).

    def _found_via_homepage_links(href_keywords: tuple[str, ...], text_markers: tuple[str, ...]) -> bool:
        if homepage.error is not None:
            return False
        for href, text in extract_anchor_links(homepage.body):
            if href_path_matches(href, href_keywords):
                return True
            if link_text_matches(text, text_markers):
                return True
        return False

    privacy_found = _found_via_homepage_links(PRIVACY_POLICY_HREF_KEYWORDS, PRIVACY_POLICY_LINK_TEXT_MARKERS)
    privacy_probing_incomplete = False
    privacy_probing_blocked = False
    if not privacy_found:
        for path in PRIVACY_POLICY_PATHS:
            if budget.expired:
                privacy_probing_incomplete = True
                break
            result = http_collector.safe_get(base_url.rstrip("/") + path)
            if _probe_confirms_page(result):
                privacy_found = True
                break
            if _probe_indicates_blocking(result):
                privacy_probing_blocked = True
    outcomes[privacy.CONTROL_ID_PRIVACY_POLICY] = privacy.evaluate_privacy_policy(
        privacy.LegalPageEvidence(
            found=privacy_found,
            is_client_side_rendered_site=(
                detection_unreliable or privacy_probing_incomplete or privacy_probing_blocked
            ),
        )
    )

    legal_found = _found_via_homepage_links(LEGAL_NOTICE_HREF_KEYWORDS, LEGAL_NOTICE_LINK_TEXT_MARKERS)
    legal_probing_incomplete = False
    legal_probing_blocked = False
    if not legal_found:
        for path in LEGAL_NOTICE_PATHS:
            if budget.expired:
                legal_probing_incomplete = True
                break
            result = http_collector.safe_get(base_url.rstrip("/") + path)
            if _probe_confirms_page(result):
                legal_found = True
                break
            if _probe_indicates_blocking(result):
                legal_probing_blocked = True
    outcomes[privacy.CONTROL_ID_LEGAL_NOTICE] = privacy.evaluate_legal_notice(
        privacy.LegalPageEvidence(
            found=legal_found,
            is_client_side_rendered_site=(
                detection_unreliable or legal_probing_incomplete or legal_probing_blocked
            ),
        )
    )

    # CMP et trackers tiers réutilisent uniquement homepage.body /
    # set_cookie_headers déjà récupérés — aucune requête réseau
    # supplémentaire ici, donc aucun garde-fou de budget nécessaire.
    # Limite précédemment documentée ici comme non corrigée (CMP sans
    # chemin NOT_TESTABLE) — CORRIGÉE : CMPPageEvidence.detection_uncertain
    # (ci-dessous) reprend le même signal detection_unreliable que les
    # pages légales, pour la même raison (page tronquée/SPA).
    script_srcs = _extract_script_srcs(homepage.body) if homepage.error is None else ()
    html_lower = homepage.body.lower() if homepage.error is None else ""
    from config.cmp_registry import GENERIC_CONSENT_LINK_TEXT_MARKERS, GENERIC_CONSENT_MARKERS

    html_markers = tuple(marker for marker in GENERIC_CONSENT_MARKERS if marker in html_lower)
    cookie_names = tuple(
        cookie.split("=")[0].strip() for cookie in (homepage.set_cookie_headers if homepage.error is None else ())
    )
    # Nouveau signal : lien de gestion des préférences cookies (texte visible
    # réel d'un <a>, pas une recherche aveugle) — corrige un second faux
    # négatif constaté : une bannière sans id/class reconnaissable mais avec
    # un lien "Gérer mes préférences cookies" en pied de page.
    consent_link_detected = False
    if homepage.error is None:
        for _href, text in extract_anchor_links(homepage.body):
            if link_text_matches(text, GENERIC_CONSENT_LINK_TEXT_MARKERS):
                consent_link_detected = True
                break
    cmp_evidence = privacy.CMPPageEvidence(
        script_srcs=script_srcs,
        global_js_vars_present=(),  # non détectable sans exécution JS (limitation documentée)
        cookie_names=cookie_names,
        html_markers=html_markers,
        consent_link_detected=consent_link_detected,
        detection_uncertain=detection_unreliable,
    )
    outcomes[privacy.CONTROL_ID_CMP] = privacy.evaluate_cmp_presence(cmp_evidence)

    if homepage.error is None:
        trackers = []
        for src, _ in http_collector.fetch_external_resources(homepage.body, base_url):
            host = urlparse(src if "://" in src else f"https:{src}").hostname or ""
            category = categorize_tracker_domain(host)
            if category:
                trackers.append(privacy.ThirdPartyTracker(domain=host, category=category))
        tracker_outcome = privacy.evaluate_third_party_trackers(trackers)
        if tracker_outcome is not None:
            outcomes[privacy.CONTROL_ID_TRACKERS] = tracker_outcome

    return outcomes


def _run_ai_signal_checks(base_url: str, homepage, budget: AuditTimeBudget) -> dict[str, CheckOutcome]:
    outcomes: dict[str, CheckOutcome] = {}

    if budget.expired:
        outcomes[ai_signals.CONTROL_ID_LLMS_TXT] = _budget_exceeded_outcome(ai_signals.CONTROL_ID_LLMS_TXT)
    else:
        llms_result = http_collector.safe_get(base_url.rstrip("/") + "/llms.txt")
        outcomes[ai_signals.CONTROL_ID_LLMS_TXT] = ai_signals.evaluate_llms_txt(llms_result.status_code == 200)

    if budget.expired:
        outcomes[ai_signals.CONTROL_ID_ROBOTS_BOTS] = _budget_exceeded_outcome(ai_signals.CONTROL_ID_ROBOTS_BOTS)
    else:
        robots_result = http_collector.safe_get(base_url.rstrip("/") + "/robots.txt")
        robots_has_bot_directive = False
        if robots_result.status_code == 200:
            lowered = robots_result.body.lower()
            robots_has_bot_directive = any(bot in lowered for bot in BOT_USER_AGENTS_OF_INTEREST)
        outcomes[ai_signals.CONTROL_ID_ROBOTS_BOTS] = ai_signals.evaluate_robots_bot_directives(robots_has_bot_directive)

    # Chatbot et mention IA réutilisent uniquement homepage.body déjà
    # récupéré — aucune requête réseau supplémentaire, pas de garde-fou
    # de budget nécessaire ici.
    client_side_only = _looks_like_client_side_only(homepage.body) if homepage.error is None else False
    chatbot_detected = None
    if homepage.error is None:
        html_lower = homepage.body.lower()
        chatbot_detected = any(marker in html_lower for marker in CHATBOT_SCRIPT_MARKERS)
    outcomes[ai_signals.CONTROL_ID_CHATBOT] = ai_signals.evaluate_chatbot_detected(
        chatbot_detected, dynamic_content_only=client_side_only
    )

    mention_found = False
    if homepage.error is None:
        html_lower = homepage.body.lower()
        mention_found = any(kw in html_lower for kw in AI_USAGE_MENTION_KEYWORDS)
    outcomes[ai_signals.CONTROL_ID_PUBLIC_MENTION] = ai_signals.evaluate_public_ai_usage_mention(mention_found)

    if budget.expired:
        outcomes[ai_signals.CONTROL_ID_GOVERNANCE_DOC] = _budget_exceeded_outcome(ai_signals.CONTROL_ID_GOVERNANCE_DOC)
    else:
        governance_docs = []
        for path in GOVERNANCE_DOC_PATHS:
            if budget.expired:
                break
            result = http_collector.safe_get(base_url.rstrip("/") + path)
            if result.status_code == 200:
                governance_docs.append(base_url.rstrip("/") + path)
        outcomes[ai_signals.CONTROL_ID_GOVERNANCE_DOC] = ai_signals.evaluate_governance_documentation(
            governance_docs or None
        )

    return outcomes


def compute_key_findings(catalog, outcomes: dict[str, CheckOutcome], findings_by_control_id: dict) -> list[dict]:
    """Sélection déterministe des Key Findings (cadrage red team GRC/UX) :
    tous les résultats défavorables parmi les contrôles INCLUDED (ceux qui
    ont concrètement fait baisser un score), dans l'ordre du catalogue,
    plafonné à 5. Aucun classement de gravité inventé — juste "ce qui a
    pesé sur le score", traçable et non discrétionnaire.

    "Défavorable" = score_contribution < 100 pour ce contrôle précis, sur
    un résultat effectivement évaluable (exclut NOT_APPLICABLE/NOT_TESTABLE,
    qui ne sont jamais des constats défavorables — mission §3)."""
    from config.risk_categories import RISK_CATEGORY_BY_CONTROL_ID

    candidates: list[dict] = []
    for control in catalog:
        if control.scoring_status != ScoringStatus.INCLUDED:
            continue
        outcome = outcomes.get(control.control_id)
        if outcome is None:
            continue
        if outcome.result in (ControlResult.NOT_APPLICABLE, ControlResult.NOT_TESTABLE):
            continue
        if outcome.score_contribution is None or outcome.score_contribution >= 100.0:
            continue  # favorable ou non quantifié -> pas un key finding défavorable

        finding = findings_by_control_id.get(control.control_id)
        if finding is None:
            continue

        candidates.append(
            {
                "control_id": control.control_id,
                "domain": control.domain.value,
                "constat": finding.resolved_label,
                "risk_category": RISK_CATEGORY_BY_CONTROL_ID.get(control.control_id),
                "recommendation": finding.recommendation,
            }
        )
        if len(candidates) >= 5:
            break

    return candidates


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def run_audit(url: str):
    """Orchestration complète Evidence → Check → ControlResult → Scoring.

    Retourne un tuple (AuditPayload, key_findings) — DÉCISION D'INTERFACE
    (cadrage red team) : key_findings dépend de score_contribution, qui
    n'est jamais persisté dans Finding/AuditPayload (modèle Pydantic
    verrouillé, non modifié). Calculé ici où l'information est encore
    disponible, puis renvoyé à part plutôt que de rouvrir models.py.
    Callers concernés, mis à jour explicitement : api/main.py,
    scripts/smoke_test.py, tests/test_audit_service.py."""
    from models import (
        AiGovernancePanel,
        AuditPayload,
        ContributingControl,
        PrivacySignalsScore,
        ScoreBreakdown,
        SecurityPostureScore,
    )

    try:
        target = ensure_url_is_safe(url)
    except URLValidationError as exc:
        raise AuditInputError(str(exc)) from exc

    base_url = f"{target.scheme}://{target.hostname}" + (f":{target.port}" if target.port else "")
    budget = AuditTimeBudget()
    homepage = http_collector.safe_get(base_url)

    security_outcomes = _run_security_checks(base_url, target.hostname, homepage, budget)
    privacy_outcomes = _run_privacy_checks(base_url, homepage, budget)
    ai_outcomes = _run_ai_signal_checks(base_url, homepage, budget)

    all_outcomes = {**security_outcomes, **privacy_outcomes, **ai_outcomes}

    findings = []
    findings_by_control_id: dict[str, object] = {}
    for control_id, outcome in all_outcomes.items():
        control_def = CATALOG_BY_ID.get(control_id)
        if control_def is None:
            continue  # ne devrait jamais arriver ; défensif plutôt que silencieux (cf. tests)
        finding = build_finding(outcome, control_def)
        findings.append(finding)
        findings_by_control_id[control_id] = finding

    sec_status, sec_score, sec_contributing, sec_excluded = compute_axis_score(
        FULL_CATALOG, Domain.SECURITY, all_outcomes
    )
    priv_status, priv_score, priv_contributing, priv_excluded = compute_axis_score(
        FULL_CATALOG, Domain.PRIVACY, all_outcomes
    )
    ai_observed, ai_total = compute_ai_governance_panel(FULL_CATALOG, all_outcomes)

    security_posture = SecurityPostureScore(
        status=sec_status,
        score=sec_score,
        grade=grade_from_score(sec_score) if sec_status == AxisStatus.COMPUTED else None,
        contributing_controls=[ContributingControl(**c) for c in sec_contributing],
        excluded_from_this_run=sec_excluded,
    )
    privacy_signals = PrivacySignalsScore(
        status=priv_status,
        score=priv_score,
        signal_level=signal_level_from_score(priv_score) if priv_status == AxisStatus.COMPUTED else None,
        contributing_controls=[ContributingControl(**c) for c in priv_contributing],
        excluded_from_this_run=priv_excluded,
    )
    ai_governance_panel = AiGovernancePanel(
        signals_observed_count=ai_observed,
        signals_total_count=ai_total,
        findings=[f for f in findings if CATALOG_BY_ID[f.control_id].domain == Domain.AI_GOVERNANCE],
    )

    score_breakdown = ScoreBreakdown(
        security_posture=security_posture,
        privacy_signals=privacy_signals,
        ai_governance=ai_governance_panel,
        methodology_notes=[
            "Analyse passive uniquement, sans interaction avec le site.",
            "Les signaux IA n'indiquent ni l'absence ni la conformité d'un usage de l'IA.",
            f"Au-delà de {AUDIT_TIME_BUDGET_SECONDS:.0f}s, les contrôles restants sont marqués "
            "« non concluant » plutôt que défavorables — un site lent n'est jamais pénalisé.",
        ],
    )

    payload = AuditPayload(
        audit_id=str(uuid4()),
        url=url,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        findings=findings,
        score_breakdown=score_breakdown,
        failed_modules=[cid for cid, o in all_outcomes.items() if o.result == ControlResult.NOT_TESTABLE],
    )

    key_findings = compute_key_findings(FULL_CATALOG, all_outcomes, findings_by_control_id)

    return payload, key_findings
