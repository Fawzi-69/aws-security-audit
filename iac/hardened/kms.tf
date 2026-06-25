# CMK avec rotation automatique activée et politique de clé explicite — CIS 3.x.
resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} CMK (rotation activée)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.this.key_id
}

# Administration réservée au compte ; usage chiffrement délégué à CloudTrail.
data "aws_iam_policy_document" "kms" {
  # Faux positifs sur une *key policy* : le « * » désigne la clé elle-même
  # (le document EST attaché à la ressource clé), et l'admin par le root du
  # compte est la pratique recommandée par AWS pour ne pas se verrouiller dehors.
  #checkov:skip=CKV_AWS_109:Key policy — « * » = la clé portée par le document.
  #checkov:skip=CKV_AWS_111:Key policy — admin root du compte recommandé par AWS.
  #checkov:skip=CKV_AWS_356:Key policy — la ressource « * » désigne la clé elle-même.
  statement {
    sid       = "EnableAccountAdmin"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}
