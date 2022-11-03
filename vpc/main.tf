module "vpc" {
  source = "./vpc-module"
}

output "network_interface_id" {
  description = "ID of project VPC"
  value       = module.vpc.network_interface_id
}