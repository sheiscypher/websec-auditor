"""
Patterns de détection de motifs de secrets (sec.secrets.pattern_detected).

Rappel méthodologique (SPEC.md §8.7 / mission §3) : une correspondance ici
est un FAIT ("un motif correspondant à ce format a été trouvé"), jamais une
preuve qu'un secret est actif. checks/secrets.py ne doit jamais transformer
une correspondance en "secret confirmé".

Liste V1, non exhaustive par construction (un sous-ensemble représentatif
suffit pour la V1 ; l'extension du catalogue de patterns est un changement
de configuration, pas de logique).
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    SecretPattern("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}")),
    SecretPattern("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern("Stripe live secret key", re.compile(r"sk_live_[A-Za-z0-9]{16,}")),
    SecretPattern("Stripe live publishable key", re.compile(r"pk_live_[A-Za-z0-9]{16,}")),
    SecretPattern("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    SecretPattern("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    SecretPattern("Generic JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    SecretPattern("DB connection string", re.compile(r"(postgres|mysql)://[^\s\"']+:[^\s\"']+@[^\s\"']+")),
)

# Marqueurs indiquant un contexte de test/exemple/placeholder — utilisés par
# sec.secrets.corroborated_signal pour NE PAS corroborer un motif détecté
# dans un contexte manifestement non exploitable.
PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "xxxx",
    "your_key_here",
    "example",
    "sample",
    "placeholder",
    "redacted",
    "changeme",
    "0000000000",
)

NON_PRODUCTION_PATH_MARKERS: tuple[str, ...] = (
    "/test/",
    "/tests/",
    "/example/",
    "/examples/",
    "/sample/",
    "/samples/",
    "/mock/",
    "/fixtures/",
)
