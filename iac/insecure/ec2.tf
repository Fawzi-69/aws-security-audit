# VULNÉRABLE À DESSEIN — voir iac/hardened/ec2.tf.

# Instance EC2 : IMDSv1 toléré (http_tokens optionnel), volume racine non chiffré.
resource "aws_instance" "app" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  # IMDSv1 reste autorisé → risque de vol de credentials via SSRF.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    volume_size = 8
    encrypted   = false
  }

  tags = {
    Name = "${var.name_prefix}-app"
  }
}

# Security group laissant SSH ouvert au monde entier.
resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app-sg"
  description = "Demo SG ouvert"

  ingress {
    description = "SSH depuis Internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
