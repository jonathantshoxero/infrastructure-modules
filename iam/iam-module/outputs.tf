output "instance_profile_id" {
  description = "ID of project VPC"
  value       = aws_iam_instance_profile.test_profile.id
}