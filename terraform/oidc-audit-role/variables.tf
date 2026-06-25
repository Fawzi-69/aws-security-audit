variable "region" {
  description = "Région AWS où créer le rôle (IAM est global, la région sert au provider)."
  type        = string
  default     = "eu-west-3"
}

variable "role_name" {
  description = "Nom du rôle d'audit assumé par la CI."
  type        = string
  default     = "github-actions-security-audit"
}

variable "github_repository" {
  description = "Dépôt autorisé à assumer le rôle, au format \"owner/repo\"."
  type        = string

  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.github_repository))
    error_message = "github_repository doit être au format \"owner/repo\"."
  }
}

variable "allowed_refs" {
  description = "Réfs git (branches/tags/environnements) autorisées via la claim sub OIDC. Par défaut, toutes."
  type        = list(string)
  default     = ["*"]
}

variable "create_oidc_provider" {
  description = "Créer le provider OIDC GitHub. Mettre à false s'il existe déjà dans le compte."
  type        = bool
  default     = true
}

# Empreintes du CA GitHub Actions. AWS valide désormais via sa propre librairie
# de CA ; ces valeurs restent acceptées pour compatibilité.
variable "oidc_thumbprints" {
  description = "Liste d'empreintes du certificat racine du provider OIDC GitHub."
  type        = list(string)
  default = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}
