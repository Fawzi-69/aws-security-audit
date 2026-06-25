# Grille de remédiation priorisée

_Généré le 2026-06-25 20:05 UTC. Total : 20 findings._

| # | Sévérité | Source | Contrôle | Ressource | Impact / constat | Correctif |
|---|----------|--------|----------|-----------|------------------|-----------|
| 1 | Critique | checkov | `CKV_AWS_24` | `aws_security_group.app` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | Restreindre l'ingress SSH à un CIDR de confiance, jamais 0.0.0.0/0. |
| 2 | Critique | prowler | `iam_no_root_access_key` | `root` | Ensure no root account access key exists | Supprimer toute access key associée au compte root ; n'utiliser le root qu'exceptionnellement avec MFA. |
| 3 | Critique | tfsec | `aws-ec2-no-public-ingress-sgr` | `aws_security_group.app` | Security group rule allows ingress from public internet on port 22 | Restreindre cidr_blocks à une plage privée. |
| 4 | Élevée | checkov | `CKV_AWS_20` | `aws_s3_bucket_acl.app` | Ensure the S3 bucket does not allow READ permissions to everyone | Retirer l'ACL public-read ; gérer l'accès via des policies restreintes. |
| 5 | Élevée | checkov | `CKV_AWS_53` | `aws_s3_bucket_public_access_block.app` | Ensure S3 bucket has block public ACLs enabled | Activer block_public_acls = true sur le public access block du bucket. |
| 6 | Élevée | checkov | `CKV_AWS_79` | `aws_instance.app` | Ensure Instance Metadata Service Version 1 is not enabled | Imposer IMDSv2 : metadata_options { http_tokens = "required" }. |
| 7 | Élevée | prowler | `iam_password_policy_minimum_length_14` | `account_password_policy` | Ensure IAM password policy requires minimum length of 14 or greater | Porter minimum_password_length à 14 dans la politique de mot de passe du compte. |
| 8 | Élevée | prowler | `iam_root_mfa_enabled` | `root` | Ensure MFA is enabled for the root account | Activer un dispositif MFA matériel ou virtuel sur le compte root. |
| 9 | Élevée | tfsec | `aws-ec2-enforce-http-token-imds` | `aws_instance.app` | Instance does not require IMDS access to require a token | Définir http_tokens = required dans metadata_options. |
| 10 | Élevée | tfsec | `aws-s3-block-public-acls` | `aws_s3_bucket_public_access_block.app` | S3 Access block should block public ACL | Mettre block_public_acls à true. |
| 11 | Moyenne | checkov | `CKV_AWS_145` | `aws_s3_bucket.app` | Ensure that S3 buckets are encrypted with KMS by default | Ajouter aws_s3_bucket_server_side_encryption_configuration avec une CMK KMS. |
| 12 | Moyenne | checkov | `CKV_AWS_67` | `aws_cloudtrail.this` | Ensure CloudTrail is enabled in all Regions | Mettre is_multi_region_trail = true. |
| 13 | Moyenne | checkov | `CKV_AWS_7` | `aws_kms_key.this` | Ensure rotation for customer created CMKs is enabled | Activer enable_key_rotation = true sur la CMK. |
| 14 | Moyenne | checkov | `CKV_AWS_8` | `aws_instance.app` | Ensure all data stored in the Launch configuration EBS is securely encrypted | Chiffrer le volume racine : root_block_device { encrypted = true }. |
| 15 | Moyenne | prowler | `cloudtrail_multi_region_enabled` | `default-trail` | Ensure CloudTrail is enabled in all regions | Configurer un trail multi-régions couvrant les events de management et les services globaux. |
| 16 | Moyenne | prowler | `ec2_ebs_default_encryption` | `ebs-encryption-default` | Ensure EBS volume encryption is enabled by default | Activer le chiffrement EBS par défaut au niveau du compte/région. |
| 17 | Moyenne | tfsec | `aws-ec2-enable-at-rest-encryption` | `aws_instance.app` | Root block device is not encrypted | Mettre encrypted = true sur root_block_device. |
| 18 | Moyenne | tfsec | `aws-s3-encryption-customer-key` | `aws_s3_bucket.app` | S3 encryption should use Customer Managed Keys | Configurer le chiffrement SSE-KMS avec une CMK. |
| 19 | Faible | checkov | `CKV_AWS_36` | `aws_cloudtrail.this` | Ensure CloudTrail log file validation is enabled | Mettre enable_log_file_validation = true. |
| 20 | Faible | prowler | `iam_rotate_access_keys_90_days` | `user/ci-legacy` | Ensure access keys are rotated every 90 days or less | Faire tourner ou désactiver toute access key de plus de 90 jours. |
