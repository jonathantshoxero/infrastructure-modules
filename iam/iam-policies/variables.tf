variable "iam_policy_name" {
  description = "Name of IAM Policy"
  type        = string
}

variable "iam_policy_description" {
  description = "Name of IAM Policy Description"
  type        = string
}

variable "policy" {
  description = "The JSON Encoded value of the policy itself"
}