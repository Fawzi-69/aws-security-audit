# Démarche d'audit

Audit de sécurité d'un compte AWS, en **lecture seule**, reproductible en local et en CI.
L'objectif : établir un état des lieux mesurable, prioriser, remédier, puis prouver la fermeture.

## 1. Cadrage & accès
- Définir le périmètre : compte(s), régions, services concernés.
- Provisionner l'accès d'audit via le module [`terraform/oidc-audit-role`](../terraform/oidc-audit-role) :
  rôle **read-only** (`SecurityAudit` + `ViewOnlyAccess`) assumé par la CI en **OIDC**, sans clé statique.
- Principe directeur : **moindre privilège**. L'audit ne doit jamais pouvoir modifier le compte.

## 2. Collecte automatisée (Prowler)
- Exécution de Prowler sur le référentiel **CIS AWS Benchmark** (`cis_3.0_aws` par défaut).
- Lancement local (`make audit`, credentials de l'auditeur) ou CI (`audit.yml`, rôle OIDC).
- Sortie machine (JSON OCSF) + formats lisibles (HTML/CSV) horodatés dans `reports/`.

## 3. Scan IaC (Checkov + tfsec)
- Analyse du Terraform **avant déploiement** : on corrige la cause à la source, pas en production.
- Gate dur sur le Terraform durci ; démonstration de détection sur le Terraform volontairement vulnérable.

## 4. Triage & priorisation
- Consolidation multi-sources (Prowler + Checkov + tfsec) en findings normalisés via
  [`scripts/generate_report.py`](../scripts/generate_report.py) : déduplication, sévérité homogène.
- Classement par sévérité (Critique → Info), puis par effort/impact.
- Faux positifs et risques acceptés : documentés (allowlist Prowler, `#checkov:skip` justifiés), jamais silencieux.

## 5. Remédiation
- Pour chaque finding : correctif concret, illustré en Terraform **avant/après**
  (voir [`iac/insecure`](../iac/insecure) vs [`iac/hardened`](../iac/hardened)).
- Livrable : la [grille de remédiation](remediation-grid.md) priorisée.

## 6. Re-test
- Relancer audit + scan après correction pour vérifier la fermeture effective des findings.
- Intégration continue : `iac-scan.yml` bloque toute régression sur le périmètre durci.

## Niveaux de sévérité
| Niveau   | Sens                                                        |
|----------|-------------------------------------------------------------|
| Critique | Exploitation directe / exposition de données ou du compte.  |
| Élevée   | Affaiblissement majeur d'un contrôle de sécurité.           |
| Moyenne  | Écart de conformité à corriger sans urgence immédiate.      |
| Faible   | Durcissement complémentaire / hygiène.                      |
| Info     | Observation, sans action requise.                           |
