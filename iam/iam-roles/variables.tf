variable "iam_role_name" {
  description = "Name of IAM Role"
  type        = string
}

variable "iam_role_description" {
  description = "Name of IAM Policy Description"
  type        = string
}

variable "assume_role_policy" {
  description = "Name of policy the IAM role is assuming"
  #type        = string TODO: define type
}