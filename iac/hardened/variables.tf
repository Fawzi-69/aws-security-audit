variable "region" {
  description = "Région AWS de déploiement."
  type        = string
  default     = "eu-west-3"
}

variable "name_prefix" {
  description = "Préfixe de nommage des ressources."
  type        = string
  default     = "demo-hardened"
}

variable "ami_id" {
  description = "AMI utilisée par l'instance d'exemple."
  type        = string
  default     = "ami-0123456789abcdef0"
}

variable "ssh_cidr" {
  description = "Plage CIDR autorisée à joindre SSH (jamais 0.0.0.0/0)."
  type        = string
  default     = "10.0.0.0/16"
}
