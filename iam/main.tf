module "iam" {
  source = "./iam-module"
  iam_group_name  = var.iam_group_name
}

variable "iam_group_name" {}

output "instance_profile_id" {
  description = "ID of project VPC"
  value       = module.iam.instance_profile_id
}