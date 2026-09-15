# WebSec Auditor V2 — SPEC.md

*Document de référence unique. Toute divergence entre le code et ce document doit être résolue en révisant ce document en premier, jamais en s'y référant implicitement.*

Version 2.0-spec | Statut : modèle fonctionnel verrouillé | Aucune implémentation de pipeline à ce stade.

---

## 1. Positionnement du produit

WebSec Auditor V2 est un **outil d'aide au diagnostic et de pré-audit passif**, destiné en priorité à des consultants GRC, DPO et analystes cybersécurité pour cadrer rapidement une première lecture d'un site web.

Ce n'est **pas** un SaaS commercial. C'est un projet de portfolio devant être professionnel, cohérent et techniquement crédible, sans chercher à couvrir tous les cas d'usage.

### Interdictions absolues de positionnement

L'outil ne doit **jamais** être présenté, ni implicitement laisser penser qu'il :

- réalise un pentest ou un test d'intrusion ;
- certifie la sécurité d'un site ;
- certifie ou évalue la conformité RGPD d'un traitement ;
- détermine la classification AI Act d'un système ou sa conformité réglementaire ;
- fournit un avis juridique ;
- détecte l'ensemble des vulnérabilités d'une cible ;
- remplace un consultant, un auditeur ou un DPO.

Ces interdictions s'appliquent au produit fini (rapport, dashboard, README) et non uniquement à la documentation interne.

---

## 2. Personas

| Persona | Besoin | Niveau de lecture |
|---|---|---|
| Consultant GRC / DPO en mission | Vision synthétique risque/conformité pour cadrer une mission | Vue synthétique |
| Analyste cyber / pentester junior | Reconnaissance passive avant audit approfondi, détail technique exploitable | Vue technique |
| Lecteur du portfolio (recruteur, jury) | Évaluer la rigueur méthodologique | Les deux vues + le présent SPEC |

Les deux premiers personas lisent **le même rapport**, à deux niveaux de profondeur — il n'existe pas deux systèmes de scoring ou deux jeux de données différents selon le lecteur.

---

## 3. Les trois domaines

| Domaine | Statut | Rôle |
|---|---|---|
| **Web Security Signals** | Scoré | Contrôles techniques passifs objectivement vérifiables et porteurs d'un état favorable/défavorable |
| **Privacy Technical Signals** | Scoré, prudemment | Éléments observables sur le site, jamais présentés comme une évaluation de conformité RGPD |
| **AI & Governance Signals** | Non scoré | Signaux indicatifs sur l'usage et la gouvernance de l'IA, sans conclusion de conformité |

Il n'existe **aucun score global fusionnant les trois domaines**. Si les scores sont affichés côte à côte, c'est toujours sous forme de juxtaposition explicite ("Web Security Signals : X/100 · Privacy Technical Signals : Y/100"), jamais un chiffre unique.

---

## 4. `evidence_level` — niveau de preuve

| Niveau | Définition |
|---|---|
| **A** | Fait objectivement observable, sans ambiguïté |
| **B** | Signal utile mais non probant à lui seul |
| **C** | Nécessite un jugement humain, métier ou juridique |
| **D** | Non concluable depuis un audit passif d'un site public |

Principe directeur : **plus le niveau de preuve est faible, moins l'outil formule de conclusion.** Un contrôle B ne devient jamais une certitude dans le wording. Un contrôle C n'est jamais transformé en conclusion automatisée. Les contrôles D ne sont pas implémentés — ils sont cités dans les limites méthodologiques (section 10) pour couper court à toute attente.

---

## 5. `scoring_status` — décision de scoring, indépendante du niveau de preuve

| Statut | Signification |
|---|---|
| **INCLUDED** | Le contrôle contribue au score de son axe |
| **EXCLUDED** | Le contrôle est affiché comme finding informatif, mais ne contribue à aucun score |

**Règle non négociable** : `scoring_status` est une décision méthodologique déclarée explicitement dans le catalogue, jamais déduite de `evidence_level`. Un contrôle de niveau A peut être `EXCLUDED` (ex. `sec.cms_detection` : fait factuel, mais sans notion de résultat favorable/défavorable). Le moteur de scoring ne doit **jamais** lire `evidence_level` pour décider si un contrôle compte dans le score — il lit exclusivement `scoring_status`.

**Test de recevabilité d'un contrôle `INCLUDED`** (appliqué à chaque contrôle du catalogue, section 8) :
> Ce contrôle mesure-t-il réellement une propriété de sécurité ou de confidentialité dont l'état peut raisonnablement contribuer à un score ? Si non → `EXCLUDED`, conservé comme finding informatif.

---

## 6. États de résultat d'un contrôle

| État | Signification |
|---|---|
| `OBSERVED` | L'élément recherché a été positivement constaté |
| `ABSENT` | L'élément recherché n'a pas été constaté |
| `PARTIAL` | Constat intermédiaire (ex. anomalie non critique) |
| `NOT_APPLICABLE` | Le contrôle ne s'applique pas structurellement à cette cible (ex. pas de MX record) |
| `NOT_TESTABLE` | Le contrôle s'applique mais n'a pas pu être exécuté cette fois (timeout, blocage, contenu inaccessible) |

Distinction impérative entre `NOT_APPLICABLE` (structurel, propre à la cible) et `NOT_TESTABLE` (conjoncturel, propre à l'exécution de cet audit) — les deux sortent du calcul de score mais ne doivent pas être confondus dans le wording du rapport.

---

## 7. Règles de scoring

### 7.1 Principe général

- Le score d'un axe est calculé **uniquement** à partir des contrôles `INCLUDED` de cet axe dont le résultat est `OBSERVED`, `ABSENT` ou `PARTIAL` pour l'audit en cours.
- Les contrôles `EXCLUDED` n'entrent **jamais** dans un calcul de score, quel que soit leur `evidence_level`.
- Les contrôles `INCLUDED` dont le résultat est `NOT_APPLICABLE` ou `NOT_TESTABLE` pour cet audit sont retirés du dénominateur, et leur poids est redistribué proportionnellement entre les contrôles `INCLUDED` effectivement évalués.
- Si, pour un axe donné, **aucun** contrôle `INCLUDED` n'est évaluable sur cet audit → l'axe est marqué **`NOT_COMPUTABLE`**. Il n'est jamais affiché comme un score numérique basé sur un dénominateur vide.

### 7.2 Pondération

Méthode retenue pour le MVP : **équipondération** entre tous les contrôles `INCLUDED` d'un même axe (poids = `1 / nombre de contrôles INCLUDED de l'axe`).

Justification à conserver telle quelle dans toute communication sur le projet (README, entretien) :
> *En l'absence de données empiriques (fréquence réelle d'exploitation, retour d'incidents) permettant de justifier objectivement une pondération différenciée entre contrôles, la V2 applique une pondération égale entre tous les contrôles inclus dans chaque axe. Ce choix est documenté pour être révisé, pas pour être caché.*

Toute évolution vers une pondération différenciée (V2.1+) doit s'appuyer sur un référentiel écrit et versionné avant d'être appliquée au moteur — jamais de poids ajusté "à l'intuition" dans le code.

### 7.3 Algorithme de calcul d'un axe (spécification, pour implémentation ultérieure dans `scoring.py`)

```
fonction calculer_score_axe(contrôles_du_catalogue, résultats_de_l_audit):
    contrôles_inclus = [c pour c in contrôles_du_catalogue si c.scoring_status == INCLUDED]

    contrôles_évaluables = [c pour c in contrôles_inclus
                             si résultats_de_l_audit[c.control_id].result
                                not in {NOT_APPLICABLE, NOT_TESTABLE}]

    si contrôles_évaluables est vide:
        retourner AxisScore(status=NOT_COMPUTABLE, contributing_controls=[])

    poids_unitaire = 1 / longueur(contrôles_évaluables)

    score = somme(
        poids_unitaire * valeur_normalisée(résultats_de_l_audit[c.control_id].result)
        pour c in contrôles_évaluables
    ) * 100

    retourner AxisScore(
        status=COMPUTED,
        score=score,
        grade=grade_depuis_score(score),   # uniquement pour Web Security Signals, cf. 7.4 — NON affiché dans l'UI (retiré du rendu, cadrage red team), conservé dans les données
        contributing_controls=contrôles_évaluables,
        excluded_from_this_run=contrôles_inclus - contrôles_évaluables
    )
```

`valeur_normalisée(result)` : `OBSERVED`/`ABSENT` → 0 ou 100 selon la sémantique propre au contrôle (cf. catalogue, section 8, colonne "logique de scoring") ; `PARTIAL` → valeur intermédiaire définie par contrôle (typiquement 50).

Le moteur ne contient **aucune branche conditionnelle basée sur `evidence_level`**. Toute tentative d'inclure/exclure un contrôle du score sur la base de son niveau de preuve constitue une violation de cette spécification.

### 7.4 Grade

- **Web Security Signals** : grade A–F calculé et disponible dans les données, mais **non affiché dans l'interface** (cadrage red team GRC/UX — une lettre scolaire comprime une nuance réelle en un jugement binaire ; la restitution privilégie "X/8 contrôles applicables" à côté du score).
- **Privacy Technical Signals** : **pas de grade en lettre.** Échelle qualitative : *Signaux limités* (0–39) / *Signaux partiels* (40–74) / *Signaux étendus* (75–100). Le choix d'éviter la lettre est délibéré : une notation A–F évoque une certification, ce que ce score ne doit jamais suggérer.
- **AI & Governance Signals** : ni score, ni grade. Affichage : "X signaux observés / Y contrôles disponibles".

### 7.5 Hard caps

Conservés du système existant, appliqués **à l'intérieur** d'un axe uniquement (jamais inter-axes) :
- `sec.tls` en anomalie critique (`ABSENT`) → plafonne le Web Security Signals Score, plafond exact à définir en implémentation mais documenté et testé (non arbitraire au moment du code). **Décision verrouillée ultérieurement (implémentation V1) : aucun hard cap introduit** — TLS reste un contrôle scoré normal comme les 7 autres.

---

## 8. Catalogue des contrôles

### 8.1 Web Security Signals — scoré (8 contrôles, poids 1/8 = 12,5 % chacun, uniforme)

Renommé depuis "Security Posture" (cadrage red team GRC/UX) : le terme "posture" implique une couverture globale de l'état de sécurité qu'un audit passif à 8 contrôles ne peut prétendre représenter. "Web Security Signals" décrit précisément ce que l'axe mesure — des signaux observables, pas une évaluation exhaustive.

Définition méthodologique verrouillée : *Cet indicateur mesure la présence de pratiques de configuration technique de base, publiquement observables sur la surface externe du domaine — il ne mesure ni le niveau global de sécurité, ni la probabilité de compromission, ni un niveau de conformité.*

Équipondération conservée et justifiée par cette redéfinition : le score compte chaque pratique une fois, sans prétendre qu'une pratique compte plus qu'une autre — cohérent avec un score qui mesure la présence de pratiques, pas le risque réel (qui nécessiterait une base empirique absente ici).

| control_id | evidence_level | scoring_status | Logique de scoring | NOT_TESTABLE / NOT_APPLICABLE | Libellé rapport |
|---|---|---|---|---|---|
| `sec.headers` | A | INCLUDED | `(nb en-têtes corrects / 6) × 100` — critères déterministes section 8.4 | Connexion impossible avant lecture des headers → `NOT_TESTABLE` | En-têtes de sécurité HTTP |
| `sec.tls` | A | INCLUDED | `OBSERVED`=100, `PARTIAL`=50, `ABSENT` (critique)=0 + hard cap — critères section 8.5 | Échec handshake réseau (timeout/reset) → `NOT_TESTABLE` | Configuration TLS |
| `sec.exposed_files` | A | INCLUDED | `ABSENT`=100, `OBSERVED`=0 | Tous les chemins bloqués (WAF) → `NOT_TESTABLE` | Chemins sensibles testés |
| `sec.secrets.pattern_detected` | A | INCLUDED | `ABSENT`=100, `OBSERVED`=0 | Contenu inaccessible → `NOT_TESTABLE` | Motifs de secrets potentiels |
| `sec.dns.dnssec` | A | INCLUDED | `OBSERVED`=100, `ABSENT`=0 | Résolution DNS impossible → `NOT_TESTABLE` | DNSSEC |
| `sec.email_security` | A | INCLUDED | `OBSERVED`(SPF+DMARC stricts)=100, `PARTIAL`=50, `ABSENT`=0 | Aucun enregistrement MX → `NOT_APPLICABLE` (structurel) | Sécurité e-mail (SPF/DMARC) |
| `sec.supply_chain.sri` | A | INCLUDED | `(nb ressources externes avec SRI / nb ressources externes testées) × 100` | Aucune ressource externe chargée → `NOT_APPLICABLE` (structurel) | Intégrité des ressources tierces (SRI) |
| `sec.cookies.secure_httponly` | A | INCLUDED | `(nb cookies Secure+HttpOnly / nb cookies posés) × 100` | Aucun cookie posé → `NOT_APPLICABLE` (structurel) | Attributs de sécurité des cookies (Secure/HttpOnly) |

### 8.2 Web Security Signals — informatif (jamais scoré)

| control_id | evidence_level | Libellé rapport |
|---|---|---|
| `sec.cms_detection` | A | Technologie/CMS détectée — fait factuel, aucune notion de résultat favorable/défavorable |
| `sec.cms_cve_mapping` | B | CVE potentiellement associée(s) à la technologie détectée |
| `sec.secrets.corroborated_signal` | B | Signal renforçant la probabilité qu'un motif détecté soit un secret actif |
| `sec.supply_chain.outdated_library` | B | Bibliothèque potentiellement obsolète |
| `sec.cookies.samesite_distribution` | B | Répartition SameSite des cookies — valeur `None` légitime dans de nombreux contextes, jamais scorable sans ambiguïté |
| `sec.security_txt.presence` | A | Fichier security.txt (RFC 9116) — adoption encore faible même chez des organisations matures, jamais scoré pour ne pas pénaliser injustement une pratique émergente |

### 8.3 Privacy Technical Signals — scoré (3 contrôles, poids 1/3 ≈ 33,3 % chacun) / informatif

| control_id | evidence_level | scoring_status | Logique de scoring | NOT_TESTABLE | Libellé rapport |
|---|---|---|---|---|---|
| `priv.legal_pages.privacy_policy` | A | INCLUDED | `OBSERVED`=100, `ABSENT`=0 | Contenu généré côté client non détectable → `NOT_TESTABLE` | Politique de confidentialité |
| `priv.legal_pages.legal_notice` | A | INCLUDED | `OBSERVED`=100, `ABSENT`=0 | Idem | Mentions légales |
| `priv.cmp.presence` | A | INCLUDED | `OBSERVED`=100, `ABSENT`=0 | CMP chargée dynamiquement, non détectée → `NOT_TESTABLE` | Plateforme de gestion du consentement (CMP) |
| `priv.trackers.third_party_detected` | B | EXCLUDED | — (informatif) | — | Trackers tiers détectés avant interaction |

Le contrôle « cohérence du refus/acceptation du consentement » (niveau C) est **absent du catalogue**, pas seulement du score — décision actée et non révisable sans nouvelle discussion de cadrage.

### 8.4 AI & Governance Signals — tous informatifs, tous `EXCLUDED`

| control_id | evidence_level | Libellé rapport |
|---|---|---|
| `ai.llms_txt.presence` | A | Fichier llms.txt |
| `ai.robots_bot_directives` | A | Directives bots IA (robots.txt) |
| `ai.chatbot_detected` | B | Interface conversationnelle détectée |
| `ai.public_ai_usage_mention` | B | Mention publique d'usage de l'IA |
| `ai.governance_documentation_public` | C | Documentation de gouvernance IA publique |

### 8.5 Critères déterministes — `sec.headers`

| En-tête | Configuration correcte |
|---|---|
| `Strict-Transport-Security` | Présent, `max-age >= 31536000` |
| `Content-Security-Policy` | Présent, sans `unsafe-inline`/`unsafe-eval` dans `script-src`/`default-src`, sans wildcard `*` en source de script |
| `X-Frame-Options` | Présent, valeur `DENY` ou `SAMEORIGIN` |
| `X-Content-Type-Options` | Présent, valeur exacte `nosniff` |
| `Referrer-Policy` | Présent, valeur dans `{no-referrer, no-referrer-when-downgrade, same-origin, strict-origin, strict-origin-when-cross-origin}` |
| `Permissions-Policy` | Présent, restreint au moins une fonctionnalité sensible (caméra, micro, géolocalisation) |

Chaque en-tête vaut 1 point binaire (correct=1 / incorrect ou absent=0). Score = `(somme des points / 6) × 100`.

### 8.6 Critères déterministes — `sec.tls`

| Cas | Critère |
|---|---|
| Anomalie critique (`ABSENT`) | Certificat expiré, OU protocole SSLv3/TLS1.0/TLS1.1 négocié, OU incohérence hostname/certificat, OU certificat auto-signé sur domaine public |
| Anomalie non critique (`PARTIAL`) | Certificat expirant sous 30 jours, OU TLS1.2 négocié sans TLS1.3 disponible côté serveur |
| Favorable (`OBSERVED`) | Certificat valide (>30 jours), TLS1.3 disponible, aucune anomalie critique |
| Non testable | Échec de connexion/handshake (timeout, reset) — distinct d'un refus explicite de négociation (anomalie critique) |

### 8.7 Reformulation — `sec.exposed_files`

Le finding ne dit **jamais** "fichier sensible exposé" ni n'affirme une compromission. Formulation imposée :
- `ABSENT` : *"Aucun chemin sensible testé n'est accessible."*
- `OBSERVED` : *"Chemin accessible détecté parmi les chemins sensibles testés : [chemin] — vérification recommandée."*
- `NOT_TESTABLE` : *"Contrôle non concluant : requêtes bloquées par la cible."*

Le filtrage par content-type/mots-clés réduit les faux positifs de détection ; il n'est jamais présenté comme une preuve d'exposition de données réelle.

---

## 9. Restitution — structure du rapport

Un seul jeu de données, deux vues.

**Structure verrouillée (7 blocs distincts, cadrage red team GRC/UX)** : Positionnement/périmètre → Synthèse (Web Security Signals, Privacy Technical Signals, AI & Governance Signals) → Points d'attention prioritaires ("Key Findings", 3-5 résultats défavorables scorés max, avec catégorie de risque catégorielle — jamais un score de risque) → Contrôles (liste complète) → Preuves techniques (détail par contrôle, bloc séparé) → Vérification humaine requise (filtre automatique sur `evidence_level == C`) → Limites méthodologiques (toujours visibles, jamais en annexe).

**Vue technique** (dépliable par finding) : contrôle exécuté → résultat → preuve → `evidence_level` → méthode de détection → référence (RFC/OWASP/CNIL, citée jamais interprétée) → limitation propre au contrôle → recommandation (uniquement si `evidence_level` A ou B — jamais pour C/D, où la seule "recommandation" possible est déjà portée par le niveau de preuve lui-même).

---

## 10. Wording — règles imposées

Interdit, quel que soit le niveau de preuve : *"Site sécurisé"*, *"Site conforme RGPD"*, *"Conforme à l'AI Act"*, *"Vulnérabilité confirmée"* (hors preuve directe), *"Aucun risque"*, *"Secret exposé/confirmé"* (l'outil ne peut jamais le confirmer sans exploitation active, exclue par ADR).

Formulations imposées selon le niveau de preuve : *"Contrôle technique observé"*, *"Signal détecté"*, *"Point d'attention"*, *"Vérification recommandée"*, *"Non déterminable par analyse passive"*, *"Preuve observée"*, *"Risque potentiel"*, *"Nécessite une analyse complémentaire"*.

**Contrainte technique impérative** : ces formulations doivent être centralisées dans un fichier de constantes de wording (un seul point de vérité), jamais rédigées en texte libre dans chaque module de contrôle — sinon un module ajouté en V2.1 réintroduira une formulation interdite par habitude.

---

## 11. Limites méthodologiques (affichées dans le produit, pas seulement documentées)

- L'analyse est **passive** : aucune interaction (formulaire de consentement, comportement d'un chatbot) n'est testée.
- Faux négatifs probables sur les sites SPA sans rendu serveur (contenu généré côté client invisible au crawler).
- Faux positifs possibles sur les motifs de secrets et sur le rattachement CVE à une version de CMS non confirmée en exploitation réelle.
- Une technologie détectée ne signifie pas automatiquement qu'elle est vulnérable.
- Un tracker détecté ne prouve pas à lui seul une violation du RGPD.
- L'absence d'un signal IA ne signifie pas absence d'usage de l'IA ; sa présence ne signifie pas non-conformité.
- Certaines conclusions nécessitent une analyse humaine (niveau C) et ne sont, par construction, jamais automatisées par l'outil.
- L'outil ne peut pas confirmer qu'un motif détecté est un secret réellement actif sans l'utiliser — ce qui constituerait une exploitation active, exclue par principe (ADR "audit passif non négociable").

---

## 12. Architecture technique (rappel — inchangée par ce document)

Mono-process, SQLite (pas de Redis ni d'architecture distribuée sans nécessité démontrée), modules de contrôle indépendants, moteur de scoring centralisé dans `scoring.py` selon l'algorithme de la section 7.3, génération de rapport à partir d'un unique payload. Le détail complet (arborescence, API, déploiement) reste celui du document de conception V2 précédent, non remis en cause ici.

---

*Fin du SPEC. Toute implémentation ultérieure doit se référer à ce document comme unique source de vérité fonctionnelle. Toute question non couverte ici doit être remontée pour clarification avant d'être tranchée dans le code.*
