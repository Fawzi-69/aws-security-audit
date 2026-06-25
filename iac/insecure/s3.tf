# VULNÉRABLE À DESSEIN — sert à démontrer la détection Checkov / tfsec.
# Voir iac/hardened/s3.tf pour la version corrigée.

# Bucket applicatif sans aucun garde-fou : pas de blocage d'accès public,
# pas de chiffrement, pas de versioning, pas de logging d'accès.
resource "aws_s3_bucket" "app" {
  bucket = "${var.name_prefix}-app"
}

# ACL publique en lecture : exposition directe des objets.
resource "aws_s3_bucket_acl" "app" {
  bucket = aws_s3_bucket.app.id
  acl    = "public-read"
}

resource "aws_s3_bucket_ownership_controls" "app" {
  bucket = aws_s3_bucket.app.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket = aws_s3_bucket.app.id

  # Tout est laissé ouvert : la politique publique n'est pas bloquée.
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
