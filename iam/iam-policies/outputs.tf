output "iam_policy_arn" {
  description = "An output of the IAM Policy ARN"
  value       = aws_iam_policy.policy.arn
}