# Security group : SSH restreint à un CIDR interne, jamais 0.0.0.0/0.
resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app-sg"
  description = "SG applicatif durci"
  vpc_id      = aws_vpc.app.id

  ingress {
    description = "SSH depuis le réseau interne"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }

  egress {
    description = "Sortie HTTPS uniquement"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

# Le default SG ne doit autoriser aucun trafic — CIS 5.4.
resource "aws_default_security_group" "app" {
  vpc_id = aws_vpc.app.id
}

# Journalisation du trafic réseau VPC vers le bucket de logs.
resource "aws_flow_log" "app" {
  vpc_id               = aws_vpc.app.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn
}

# Instance EC2 : IMDSv2 imposé, volume racine chiffré, monitoring détaillé.
resource "aws_instance" "app" {
  #checkov:skip=CKV2_AWS_41:Profil IAM hors périmètre de cet exemple de durcissement réseau/EBS.
  #checkov:skip=CKV_AWS_135:Type t3 EBS-optimized par défaut ; non requis par la démo.
  ami                    = var.ami_id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id]
  monitoring             = true
  ebs_optimized          = true

  # IMDSv2 obligatoire (jeton requis) — bloque le vol de credentials via SSRF.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 8
    encrypted   = true
    kms_key_id  = aws_kms_key.this.arn
  }

  tags = {
    Name = "${var.name_prefix}-app"
  }
}
