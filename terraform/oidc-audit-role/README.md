# Rôle d'audit OIDC (read-only)

Crée le provider OIDC GitHub Actions et un rôle IAM **strictement en lecture seule**
que la CI assume sans aucune clé statique. C'est le socle d'accès de l'audit automatisé.

## Ce qui est créé
- `aws_iam_openid_connect_provider` pour `token.actions.githubusercontent.com` (audience `sts.amazonaws.com`).
- `aws_iam_role` dont la relation de confiance n'autorise que le dépôt `github_repository`
  (et les réfs `allowed_refs`) à s'authentifier.
- Attachement des **seules** policies AWS managées `SecurityAudit` et `ViewOnlyAccess`.
  Aucune permission d'écriture, aucune policy inline.

## Déploiement
```bash
cp terraform.tfvars.example terraform.tfvars   # renseigner github_repository
terraform init
terraform plan
terraform apply
```

Puis exposer l'ARN du rôle à la CI :
```bash
terraform output -raw audit_role_arn
# -> à enregistrer dans GitHub : Settings > Secrets and variables > Actions
#    secret AWS_AUDIT_ROLE_ARN
```

## Notes
- **Moindre privilège.** Le rôle ne peut rien modifier. Si Prowler signale un manque de
  permission de lecture sur un service précis, ajouter une policy de lecture ciblée plutôt
  qu'élargir le périmètre.
- **Empreintes (`thumbprint_list`).** AWS valide aujourd'hui le certificat du provider via sa
  propre librairie de CA ; les empreintes fournies restent acceptées pour compatibilité.
- **Provider déjà présent.** Si le provider OIDC GitHub existe déjà dans le compte, passer
  `create_oidc_provider = false` : le rôle réutilisera le provider existant.
- **Restreindre l'accès.** En production, préférer `allowed_refs = ["ref:refs/heads/main"]`
  (ou un environnement GitHub) à `*` pour limiter quelles exécutions peuvent assumer le rôle.
