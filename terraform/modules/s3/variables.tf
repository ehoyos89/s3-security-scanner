# Variable para el nombre del proyecto.
# Descripción: Nombre del proyecto.
variable "project_name" {
  description = "Name of the project"
  type        = string
  
}

# Variable para el entorno.
# Descripción: Entorno (dev/prod).
variable "environment" {
  description = "Environment (dev/prod)"
  type        = string
}