# VULNÉRABLE À DESSEIN — voir iac/hardened/kms.tf.

# Clé KMS sans rotation automatique activée.
resource "aws_kms_key" "this" {
  description         = "${var.name_prefix} CMK sans rotation"
  enable_key_rotation = false
}
