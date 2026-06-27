# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Non publié]

### Ajouté
- Tests unitaires du générateur de rapport (`tests/`), avec un échantillon OCSF Prowler
  au schéma réaliste, et un job CI `tests`.
- Marquage explicite des rapports illustratifs : option `--synthetic` (bannière HTML,
  encart Markdown, champ `synthetic` dans `findings.json`). Le rapport d'exemple est désormais étiqueté.

### Modifié
- Parser OCSF Prowler durci : identifiant de contrôle via `metadata.event_code` puis repli sur
  `unmapped.check_id` / `finding_info.uid` ; sévérité acceptée en libellé texte **ou** `severity_id`
  numérique ; ressource et région cherchées à plusieurs emplacements.

## [0.1.0]

### Ajouté
- Audit Prowler (CIS AWS Benchmark) exécutable en local et en CI, en lecture seule.
- Scan IaC Checkov + tfsec : gate dur sur le Terraform durci, démonstration de détection sur l'exemple vulnérable.
- Génération de rapport consolidé (JSON, HTML, grille de remédiation) sans dépendance externe.
- Exemples de durcissement Terraform avant/après (S3, EC2/IMDSv2, IAM, KMS, CloudTrail, VPC).
- Rôle d'audit OIDC read-only (`SecurityAudit` + `ViewOnlyAccess`), sans clé statique.
- Workflows CI (`iac-scan`, `audit`), Makefile, documentation de la démarche.
