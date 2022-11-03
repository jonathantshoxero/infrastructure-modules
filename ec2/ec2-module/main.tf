resource "aws_instance" "foo" {
  ami = "ami-088d4832275406edf"
  instance_type = var.instance_type
  iam_instance_profile = var.instance_profile_id

  network_interface {
    network_interface_id = var.network_interface_id
    device_index         = 0
  }
}