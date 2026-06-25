# IaC durcie — version corrigée

Même périmètre que [`../insecure/`](../insecure/), mais conforme. Cette configuration passe
`terraform fmt`, `terraform validate`, `tflint` et `checkov` **sans aucun finding** (les checks
contextuels non pertinents pour la démo sont explicitement marqués `#checkov:skip` avec justification).

## Avant / après par contrôle

| Domaine        | Avant (`insecure/`)                          | Après (`hardened/`)                                                        | Réf. CIS |
|----------------|----------------------------------------------|----------------------------------------------------------------------------|----------|
| **S3 — accès public** | ACL `public-read`, public access block off | `public_access_block` 4×`true`, ACL retirée                                | 2.1.5    |
| **S3 — chiffrement**  | aucun                                  | SSE-KMS (CMK) + `bucket_key_enabled`                                       | 2.1.1    |
| **S3 — transit**      | non imposé                             | bucket policy `Deny` si `aws:SecureTransport = false`                       | 2.1.2    |
| **S3 — traçabilité**  | ni versioning ni logging               | versioning activé + access logging vers bucket dédié + lifecycle           | 2.1.x    |
| **EC2 — IMDS**        | IMDSv1 toléré (`optional`)             | `http_tokens = "required"` (IMDSv2)                                         | 5.6      |
| **EC2 — EBS**         | volume racine non chiffré              | `encrypted = true` + CMK KMS                                               | 5.x      |
| **Réseau**            | SSH `0.0.0.0/0`, default SG ouvert     | SSH limité à un CIDR interne, default SG verrouillé, VPC flow logs          | 5.3/5.4  |
| **IAM — mots de passe** | longueur 6, sans complexité ni rotation | longueur 14, complexité, rotation 90 j, anti-réutilisation 24             | 1.8–1.11 |
| **KMS**               | rotation désactivée                    | `enable_key_rotation = true` + key policy explicite                        | 3.8      |
| **CloudTrail**        | mono-région, sans intégrité ni chiffrement | multi-région, `log_file_validation`, chiffrement KMS, events globaux       | 3.1/3.2/3.7 |

## Vérifier en local
```bash
make tf-validate     # fmt -check + validate + tflint + checkov sur hardened/ et le rôle OIDC
```
