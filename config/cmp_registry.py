"""
Registre centralisé des CMP reconnues — mission section 8.

Toute modification de la liste se fait UNIQUEMENT ici. checks/privacy.py
ne doit contenir aucun nom de CMP en dur.

Chaque entrée porte des empreintes simples et déterministes (nom de script,
variable JS globale, cookie caractéristique). Ce ne sont pas des heuristiques
probabilistes : une correspondance exacte sur au moins une empreinte suffit
à classer CMP_RECOGNIZED. L'absence de toute correspondance mais la présence
d'un marqueur générique de bandeau cookie classe CMP_GENERIC (SPEC mission
§8 : ne jamais confondre CMP_GENERIC et NO_CMP).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CMPFingerprint:
    name: str
    script_src_patterns: tuple[str, ...] = ()
    global_js_vars: tuple[str, ...] = ()
    cookie_names: tuple[str, ...] = ()


CMP_REGISTRY: tuple[CMPFingerprint, ...] = (
    CMPFingerprint("Didomi", script_src_patterns=("sdk.privacy-center.org", "didomi"), global_js_vars=("Didomi",), cookie_names=("didomi_token",)),
    CMPFingerprint("OneTrust", script_src_patterns=("cdn.cookielaw.org", "onetrust"), global_js_vars=("OneTrust", "OnetrustActiveGroups"), cookie_names=("OptanonConsent",)),
    CMPFingerprint("Axeptio", script_src_patterns=("static.axept.io", "axeptio"), global_js_vars=("axeptioSDK", "axeptioSettings"), cookie_names=("axeptio_authorized_vendors",)),
    CMPFingerprint("Usercentrics", script_src_patterns=("app.usercentrics.eu", "usercentrics"), global_js_vars=("UC_UI",), cookie_names=("uc_settings",)),
    CMPFingerprint("Cookiebot", script_src_patterns=("consent.cookiebot.com",), global_js_vars=("Cookiebot",), cookie_names=("CookieConsent",)),
    CMPFingerprint("TrustCommander", script_src_patterns=("trustcommander", "commandersact"), global_js_vars=("tC",), cookie_names=("tc_privacy",)),
    CMPFingerprint("Tarteaucitron.js", script_src_patterns=("tarteaucitron.js", "tarteaucitron.io"), global_js_vars=("tarteaucitron",), cookie_names=("tarteaucitron",)),
    CMPFingerprint("Complianz", script_src_patterns=("complianz", "cmplz"), global_js_vars=("complianz", "cmplz_banner"), cookie_names=("cmplz_consent_status",)),
    CMPFingerprint("Quantcast", script_src_patterns=("quantcast.mgr.consensu.org", "cmp.quantcast.com"), global_js_vars=("__cmp", "__tcfapi"), cookie_names=("euconsent-v2",)),
    CMPFingerprint("CookieYes", script_src_patterns=("cdn-cookieyes.com", "cookieyes"), global_js_vars=("CookieYes",), cookie_names=("cookieyes-consent",)),
    CMPFingerprint("Osano", script_src_patterns=("cmp.osano.com", "osano"), global_js_vars=("Osano",), cookie_names=("osano_consentmanager",)),
)

# Marqueurs génériques : présence d'un mécanisme de consentement dont le
# fournisseur ne correspond à aucune empreinte du registre ci-dessus.
# Volontairement restreint à des motifs structurels (id/class/texte de
# bandeau), pas à un mot-clé isolé qui multiplierait les faux positifs.
GENERIC_CONSENT_MARKERS: tuple[str, ...] = (
    "cookie-banner",
    "cookie-consent",
    "consent-banner",
    "gdpr-banner",
    "cookie-notice",
)

# Texte visible de LIEN (pas un id/class DOM) indiquant la présence d'un
# mécanisme de gestion des préférences cookies — signal ajouté après un
# faux négatif constaté en production (cf. compte rendu) : de nombreux
# sites exposent un lien "Gérer mes préférences cookies" en pied de page
# sans que la bannière elle-même ne porte un id/class reconnaissable dans
# GENERIC_CONSENT_MARKERS. Détecté via collectors/html_parse.py sur les
# liens réellement extraits de la page, pas par recherche aveugle.
GENERIC_CONSENT_LINK_TEXT_MARKERS: tuple[str, ...] = (
    "gérer mes préférences cookies",
    "gérer les cookies",
    "préférences cookies",
    "paramètres des cookies",
    "cookie preferences",
    "manage cookies",
    "manage cookie preferences",
    "cookie settings",
)
