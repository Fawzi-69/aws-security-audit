# VULNÉRABLE À DESSEIN — voir iac/hardened/logging.tf.

# Bucket de destination des logs CloudTrail (lui-même non durci).
resource "aws_s3_bucket" "trail" {
  bucket = "${var.name_prefix}-trail"
}

# CloudTrail mono-région, sans validation d'intégrité des fichiers de logs,
# sans chiffrement KMS, sans log des events de management globaux.
resource "aws_cloudtrail" "this" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}
