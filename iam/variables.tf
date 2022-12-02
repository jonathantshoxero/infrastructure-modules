variable "env" {
  description = "Terragrunt environment at hand"
  type        = string
}

variable "admin_group" {
  description = "admin group to gain access to roles"
  type = list(string)
}