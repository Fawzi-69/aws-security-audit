# Politique de mot de passe conforme CIS 1.x :
# longueur ≥ 14, complexité, rotation 90 j, non-réutilisation des 24 derniers.
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
