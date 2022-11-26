resource "aws_iam_policy" "policy" {
  name        = var.iam_policy_name
  description = var.iam_policy_description

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = var.policy
}