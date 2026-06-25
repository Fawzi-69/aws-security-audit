# Grille de remédiation — gabarit

Modèle de restitution priorisée. La version peuplée est régénérée automatiquement
dans `reports/remediation.md` (et `reports/sample/remediation.md` pour l'exemple) à
partir des findings consolidés.

## Colonnes
| Champ            | Description                                                        |
|------------------|--------------------------------------------------------------------|
| **#**            | Rang de priorité (sévérité décroissante).                          |
| **Sévérité**     | Critique / Élevée / Moyenne / Faible / Info.                       |
| **Source**       | prowler / checkov / tfsec.                                          |
| **Contrôle**     | Identifiant du check (CIS, CKV_*, AVD-*).                           |
| **Ressource**    | Ressource AWS ou bloc Terraform concerné.                          |
| **Impact**       | Risque concret si non corrigé.                                     |
| **Correctif**    | Action de remédiation (souvent un patch Terraform avant/après).    |

## Exemple (extrait)
| # | Sévérité | Source  | Contrôle      | Ressource                | Impact                                  | Correctif                                              |
|---|----------|---------|---------------|--------------------------|-----------------------------------------|--------------------------------------------------------|
| 1 | Critique | prowler | `iam_no_root_access_key` | root                | Compromission totale du compte          | Supprimer les access keys du root ; MFA matériel       |
| 2 | Critique | checkov | `CKV_AWS_24`  | `aws_security_group.app` | SSH exposé à Internet (`0.0.0.0/0`)     | Restreindre l'ingress 22 à un CIDR de confiance        |
| 3 | Élevée   | checkov | `CKV_AWS_79`  | `aws_instance.app`       | Vol de credentials via SSRF (IMDSv1)    | `metadata_options { http_tokens = "required" }`        |
| 4 | Moyenne  | tfsec   | `aws-s3-encryption-customer-key` | `aws_s3_bucket.app` | Données au repos non chiffrées par CMK | SSE-KMS + `bucket_key_enabled`                          |

La grille complète de la démo : [`../reports/sample/remediation.md`](../reports/sample/remediation.md).
