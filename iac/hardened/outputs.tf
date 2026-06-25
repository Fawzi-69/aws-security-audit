output "app_bucket" {
  description = "Nom du bucket applicatif durci."
  value       = aws_s3_bucket.app.id
}

output "kms_key_arn" {
  description = "ARN de la CMK utilisée pour le chiffrement au repos."
  value       = aws_kms_key.this.arn
}

output "cloudtrail_arn" {
  description = "ARN du trail CloudTrail multi-région."
  value       = aws_cloudtrail.this.arn
}
