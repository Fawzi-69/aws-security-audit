# IaC volontairement non durcie

> ⚠️ **Ne pas déployer.** Ce module est vulnérable **à dessein**. Il sert uniquement à
> démontrer la détection par Checkov et tfsec, et à servir de point de comparaison avec
> `../hardened/`.

Chaque fichier reproduit une mauvaise configuration courante, mappée à un contrôle CIS AWS :

| Fichier        | Mauvaise configuration                                              | Contrôle visé          |
|----------------|---------------------------------------------------------------------|------------------------|
| `s3.tf`        | ACL `public-read`, public access block désactivé, pas de chiffrement, ni versioning, ni logging | CIS 2.1.x              |
| `ec2.tf`       | IMDSv1 toléré (`http_tokens = optional`), EBS non chiffré, SSH ouvert `0.0.0.0/0` | CIS 5.x / EC2          |
| `iam.tf`       | Politique de mot de passe faible, policy `Action:*` sur `Resource:*` | CIS 1.x                |
| `kms.tf`       | Rotation de clé KMS désactivée                                      | CIS 3.x                |
| `logging.tf`   | CloudTrail mono-région, sans validation d'intégrité ni events globaux | CIS 3.1 / 3.2          |

Pour voir la détection :

```bash
make scan-iac          # checkov + tfsec sur iac/ (les findings ici sont attendus)
```

La version corrigée — qui passe `fmt`, `validate`, `tflint` et `checkov` sans aucun finding —
est dans [`../hardened/`](../hardened/).
