"""Classification best-effort de domaines de trackers tiers connus, pour
priv.trackers.third_party_detected (informatif, EXCLUDED). Liste V1
restreinte et non exhaustive — un domaine absent de cette liste n'est
simplement pas catégorisé, pas "absent de la page" (limite documentée)."""

TRACKER_DOMAINS_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "analytics": ("google-analytics.com", "googletagmanager.com", "hotjar.com", "matomo.cloud"),
    "advertising": ("doubleclick.net", "googlesyndication.com", "ads-twitter.com", "criteo.com"),
    "social": ("connect.facebook.net", "platform.twitter.com", "platform.linkedin.com"),
}


def categorize_tracker_domain(domain: str) -> str | None:
    for category, domains in TRACKER_DOMAINS_BY_CATEGORY.items():
        if any(known in domain for known in domains):
            return category
    return None
