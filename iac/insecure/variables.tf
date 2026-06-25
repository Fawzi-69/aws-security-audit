variable "region" {
  description = "Région AWS de déploiement."
  type        = string
  default     = "eu-west-3"
}

variable "name_prefix" {
  description = "Préfixe de nommage des ressources."
  type        = string
  default     = "demo-insecure"
}
