locals {
  oidc_url     = "token.actions.githubusercontent.com"
  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
  allowed_subs = [for ref in var.allowed_refs : "repo:${var.github_repository}:${ref == "*" ? "*" : ref}"]
}

# Provider OIDC GitHub Actions (créé une seule fois par compte).
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_oidc_provider ? 1 : 0
  url             = "https://${local.oidc_url}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.oidc_thumbprints
}

# Réutilisation d'un provider existant le cas échéant.
data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.oidc_url}"
}

# Relation de confiance : seul le dépôt (et les réfs) autorisé peut assumer le rôle,
# avec l'audience sts.amazonaws.com.
data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.oidc_url}:sub"
      values   = local.allowed_subs
    }
  }
}

# Rôle d'audit : strictement lecture seule.
resource "aws_iam_role" "audit" {
  name                 = var.role_name
  description          = "Rôle read-only assumé par la CI pour l'audit de sécurité (OIDC)."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

# Périmètre limité aux managed policies AWS de lecture seule.
# Aucune permission d'écriture n'est attachée.
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/job-function/ViewOnlyAccess"
}

data "aws_partition" "current" {}
