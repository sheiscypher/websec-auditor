"""Marqueurs pour le panneau AI & Governance Signals.

AVERTISSEMENT MÉTHODOLOGIQUE (à ne pas oublier lors d'une évolution) :
- La détection de chatbot par scripts connus est un heuristique bas de
  confiance (evidence_level B) : un widget non listé ici, ou chargé
  dynamiquement après exécution JS, ne sera pas détecté (faux négatif).
- La détection de "mention publique d'usage de l'IA" par mots-clés est
  volontairement approximative — elle signale une PRÉSENCE de vocabulaire,
  pas une preuve de gouvernance réelle (cohérent avec SPEC.md §8.4).
"""

GOVERNANCE_DOC_PATHS: tuple[str, ...] = (
    "/ai-policy",
    "/politique-ia",
    "/responsible-ai",
    "/gouvernance-ia",
)

CHATBOT_SCRIPT_MARKERS: tuple[str, ...] = (
    "intercom",
    "drift.com",
    "zendesk",
    "crisp.chat",
    "tidio",
    "livechatinc",
    "chatbase",
)

AI_USAGE_MENTION_KEYWORDS: tuple[str, ...] = (
    "intelligence artificielle",
    "généré par ia",
    "généré par l'intelligence artificielle",
    "powered by ai",
    "generative ai",
    "assistant ia",
)

BOT_USER_AGENTS_OF_INTEREST: tuple[str, ...] = (
    "gptbot",
    "claudebot",
    "perplexitybot",
    "ccbot",
    "google-extended",
)
