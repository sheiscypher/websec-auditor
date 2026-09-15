# WebSec Auditor

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Audit: passif uniquement](https://img.shields.io/badge/audit-passif%20uniquement-2453c4.svg)]()
[![Statut: V1](https://img.shields.io/badge/statut-V1-lightgrey.svg)]()

Outil d'aide au diagnostic et de **pré-audit passif** d'un site web : posture de sécurité technique, signaux de confidentialité observables, et signaux liés à l'IA et à sa gouvernance.

Projet de portfolio cybersécurité / GRC — conçu pour démontrer une méthodologie de contrôle rigoureuse, pas pour remplacer un audit professionnel.

## Ce que cet outil N'EST PAS

- **Ce n'est pas un test d'intrusion.** Aucune exploitation, aucun fuzzing, aucun bruteforce. Uniquement des requêtes HTTP passives (GET/HEAD) et des résolutions DNS.
- **Ce n'est pas une certification de sécurité.** Un score élevé ne garantit pas l'absence de vulnérabilité.
- **Ce n'est pas un audit de conformité RGPD.** Le score "Privacy Technical Signals" mesure la présence d'éléments observables (page de politique de confidentialité, CMP...), jamais la conformité réelle d'un traitement de données.
- **Ce n'est pas un outil de classification AI Act.** Le panneau "AI & Governance Signals" liste des indices observables, sans aucun score et sans aucune conclusion de conformité réglementaire.
- **Ce n'est pas un avis juridique.**

## Ce que l'outil mesure

| Domaine | Statut | Exemples de contrôles |
|---|---|---|
| **Web Security Signals** | Scoré | En-têtes de sécurité HTTP, TLS, fichiers sensibles exposés, motifs de secrets, DNSSEC, SPF/DMARC, intégrité des ressources tierces (SRI), attributs de sécurité des cookies (+ CMS, security.txt en informatif) |
| **Privacy Technical Signals** | Scoré, avec prudence méthodologique | Présence d'une politique de confidentialité, de mentions légales, d'une plateforme de gestion du consentement (CMP) |
| **AI & Governance Signals** | Jamais scoré | `llms.txt`, directives bots IA, interface conversationnelle détectée, mentions publiques d'usage de l'IA |

La méthodologie complète — niveaux de preuve (A/B/C/D), statut de scoring (INCLUDED/EXCLUDED), règles de pondération, formulation imposée selon le niveau de preuve — est documentée intégralement dans [`SPEC.md`](./SPEC.md). Ce document est la source de vérité fonctionnelle du projet.

## Limites méthodologiques (à lire avant tout usage)

- L'analyse est **passive** : aucune interaction avec le site (formulaire de consentement, comportement d'un chatbot) n'est testée.
- Pas d'exécution JavaScript : les sites SPA sans rendu serveur peuvent produire des résultats incomplets, explicitement marqués `NOT_TESTABLE` plutôt que d'être interprétés à tort comme défavorables. Ressources/scripts/cookies injectés dynamiquement par JS (ex : gestionnaire de tags chargeant des trackers) restent invisibles — signalé explicitement dans le libellé du contrôle SRI concerné plutôt que présenté comme une absence certaine.
- Détection des pages légales et de la CMP : basée sur l'extraction réelle des liens de la page d'accueil (href + texte visible, normalisé pour les accents/tirets/underscores), avec un sondage direct de chemins connus en secours. Un site dont la page légale n'est ni liée depuis l'accueil ni à un chemin conventionnel restera `NOT_TESTABLE` ou `ABSENT` selon le cas — l'outil ne suit pas de liens au-delà de la page d'accueil (pas de crawl multi-page).
- Détection CMP : une page tronquée par le plafond de taille (2 Mo) peut faire manquer une CMP réelle sans que ce cas soit distingué d'une absence réelle (contrairement aux pages légales, qui ont ce garde-fou) — limite connue, non corrigée à ce stade.
- Faux positifs possibles sur les motifs de secrets et sur la détection de CMP générique.
- Une technologie détectée ne signifie pas qu'elle est vulnérable ; l'outil sépare toujours la détection de la technologie du rattachement CVE (V1 : rattachement CVE non implémenté — dépendance externe jugée disproportionnée pour cette version).
- Un tracker tiers détecté ne prouve pas une violation du RGPD.
- L'absence d'un signal IA ne prouve pas l'absence d'usage de l'IA ; sa présence ne prouve pas une gouvernance conforme.
- **Limite de sécurité active documentée, pas cachée** : la protection SSRF valide le DNS avant chaque requête, mais reste exposée à un scénario de *DNS rebinding* (changement de résolution entre la validation et la requête réelle). Une mitigation complète nécessiterait un transport HTTP à IP épinglée, jugé disproportionné pour cette V1. Voir `security/ssrf.py`.

## Architecture

```
GitHub → Render → FastAPI (api/main.py)
                       │
                services/audit_service.py   (orchestration, seule couche qui connaît tout)
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   collectors/       checks/       scoring.py
   (réseau réel,   (interprétation  (agrège les
    httpx/dns)      pure, testable   contrôles
                     sans réseau)     INCLUDED
                                      uniquement)
                       │
                  Finding / ScoreBreakdown (models.py, Pydantic)
                       │
                  Frontend statique (api/static/index.html)
```

Application monolithique volontairement simple : pas de queue, pas de worker séparé, pas de base de données (traitement synchrone par requête). Ce choix pourra être revu si les temps de réponse ou la charge le justifient — pas avant.

## Lancer en local

```bash
git clone <repository>
cd websec-auditor
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn api.main:app --reload
```

Ouvrir `http://localhost:8000`.

## Exécuter les tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Répartition :
- `test_headers.py`, `test_tls.py`, `test_cmp.py`, `test_exposure.py`, `test_secrets.py`, `test_dns_email_supply_privacy_pages.py`, `test_scoring.py`, `test_ssrf.py` : logique pure, aucune dépendance réseau.
- `test_catalog.py`, `test_models.py` : invariants du catalogue et validateurs Pydantic.
- `test_audit_service.py` : intégration du pipeline complet avec collectors **mockés** (pas de réseau réel).
- `test_api.py` : démarrage de l'application et réponse des endpoints.

Aucun test ne dépend d'un accès réseau sortant réel — la collecte réseau (`collectors/`) est mockée partout où elle intervient dans les tests automatisés. Un test manuel supplémentaire existe pour la collecte réelle :

```bash
python scripts/smoke_test.py https://example.com
```

## Déployer sur Render

1. Pousser le dépôt sur GitHub.
2. Sur Render : **New → Web Service**, connecter le dépôt.
3. Render détecte `render.yaml` (build `pip install -r requirements.txt`, démarrage `uvicorn api.main:app --host 0.0.0.0 --port $PORT`).
4. Variables d'environnement (optionnelles, valeurs par défaut déjà correctes) : `LOG_LEVEL`, `ALLOWED_ORIGINS`. Aucun secret requis en V1.
5. Chaque `git push` sur la branche par défaut déclenche un redéploiement automatique.

Vérification post-déploiement :
```bash
curl https://<votre-service>.onrender.com/health
python scripts/smoke_test.py https://<votre-service>.onrender.com
```

## Sécurité de l'outil lui-même

- Validation stricte de l'URL : schémas `http`/`https` uniquement, résolution DNS vérifiée contre les plages privées/loopback/link-local (dont les IP de métadonnées cloud), littéraux IP privés rejetés avant toute résolution.
- Chaque redirection HTTP est revalidée individuellement (pas de suivi aveugle).
- Timeout réseau sur chaque requête, taille de réponse plafonnée (2 Mo).
- Aucune exécution de JavaScript, aucun scan de ports, aucune commande shell construite à partir de l'URL.
- Erreurs techniques jamais transformées silencieusement en verdict de sécurité défavorable (`NOT_TESTABLE` explicite).
- Aucune trace d'exception brute renvoyée au client (log serveur uniquement).
- **Anti-abus du endpoint `/audit` lui-même** (`api/rate_limit.py`), distinct du throttle par domaine audité : 5 requêtes / 5 min par IP appelante, et 3 audits simultanés maximum tous appelants confondus (protège la capacité du service même face à des appels distribués sur des IP différentes).

## Statut du projet

V1. Les contrôles `sec.cms_cve_mapping` et `sec.supply_chain.outdated_library` sont définis dans le catalogue mais leur collecte n'est pas implémentée (dépendance à une base CVE externe, reportée). Les heuristiques du panneau AI & Governance sont volontairement approximatives et documentées comme telles (`config/ai_signal_paths.py`).

## Licence

MIT — voir [`LICENSE`](./LICENSE). Utilisation, modification et redistribution libres, y compris à des fins commerciales, à condition de conserver la mention de copyright et la licence.
