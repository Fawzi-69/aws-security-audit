output "audit_role_arn" {
  description = "ARN du rôle d'audit. À renseigner comme secret CI AWS_AUDIT_ROLE_ARN."
  value       = aws_iam_role.audit.arn
}

output "oidc_provider_arn" {
  description = "ARN du provider OIDC GitHub utilisé par la relation de confiance."
  value       = local.provider_arn
}
