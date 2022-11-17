resource "aws_iam_role_policy_attachment" "policy" {
  role      = var.iam_role_name
  policy_arn = var.iam_policy_arn
}