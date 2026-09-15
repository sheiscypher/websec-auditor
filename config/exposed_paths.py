"""Liste centralisée des chemins sensibles testés par sec.exposed_files.
Volontairement restreinte en V1 (portfolio) — liste courte mais
représentative plutôt qu'exhaustive, cohérent avec SPEC.md (moins de
contrôles, plus de rigueur sur chacun)."""

SENSITIVE_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/backup.zip",
    "/config.php.bak",
    "/.aws/credentials",
    "/docker-compose.yml",
    "/.htpasswd",
    "/server-status",
)
