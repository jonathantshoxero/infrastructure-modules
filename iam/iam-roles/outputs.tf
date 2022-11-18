output "iam_role_name" {
  description = "An output of the IAM role name"
  value       = aws_iam_role.test_role.name
}