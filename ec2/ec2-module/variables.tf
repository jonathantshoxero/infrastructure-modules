variable "network_interface_id" {
  description = "Network Interface Id for AWS Instance"
  type        = string
}

variable "instance_type" {
  description = "Instance of AMI SKU"
  type        = string
}

variable "instance_profile_id" {
  type = string
}