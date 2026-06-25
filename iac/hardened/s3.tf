# --- Bucket de logs d'accès S3 -------------------------------------------------
# Reçoit les access logs du bucket applicatif. Durci à l'identique, hormis
# l'auto-journalisation (un bucket de logs ne se journalise pas lui-même).
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:Bucket de logs — l'auto-journalisation créerait une récursion.
  #checkov:skip=CKV_AWS_144:Réplication cross-region hors périmètre de cette démo mono-région.
  #checkov:skip=CKV2_AWS_62:Pas de consommateur d'événements sur le bucket de logs.
  bucket = "${var.name_prefix}-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = 365
    }
  }
}

# --- Bucket applicatif ---------------------------------------------------------
resource "aws_s3_bucket" "app" {
  #checkov:skip=CKV_AWS_144:Réplication cross-region hors périmètre de cette démo mono-région.
  #checkov:skip=CKV2_AWS_62:Pas de consommateur d'événements défini pour cette démo.
  bucket = "${var.name_prefix}-app"
}

# Blocage total de l'accès public — CIS 2.1.5.
resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "app" {
  bucket = aws_s3_bucket.app.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Chiffrement au repos via la CMK KMS — CIS 2.1.1.
resource "aws_s3_bucket_server_side_encryption_configuration" "app" {
  bucket = aws_s3_bucket.app.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

# Journalisation des accès vers le bucket de logs dédié.
resource "aws_s3_bucket_logging" "app" {
  bucket        = aws_s3_bucket.app.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/"
}

resource "aws_s3_bucket_lifecycle_configuration" "app" {
  bucket = aws_s3_bucket.app.id
  rule {
    id     = "abort-incomplete-and-tier"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Refus de tout accès non chiffré en transit (TLS obligatoire) — CIS 2.1.2.
data "aws_iam_policy_document" "app_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.app.arn, "${aws_s3_bucket.app.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "app" {
  bucket = aws_s3_bucket.app.id
  policy = data.aws_iam_policy_document.app_tls.json
}
