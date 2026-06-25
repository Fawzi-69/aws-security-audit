# VULNÉRABLE À DESSEIN — voir iac/hardened/iam.tf.

# Politique de mot de passe faible : longueur minimale 6, aucune complexité,
# pas de rotation, réutilisation autorisée. Non conforme CIS.
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 6
  require_symbols                = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_lowercase_characters   = false
  allow_users_to_change_password = true
}

# Politique attachable « tous droits » : viole le moindre privilège.
resource "aws_iam_policy" "admin" {
  name        = "${var.name_prefix}-admin"
  description = "Trop permissive"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
