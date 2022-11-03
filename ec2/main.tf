module "ec2" {
  source = "./ec2-module"
  network_interface_id  = var.network_interface_id
  instance_type = var.instance_type
  instance_profile_id = var.instance_profile_id
}

variable "instance_type" {}
variable "network_interface_id" {}
variable "instance_profile_id" {}