output "network_interface_id" {
  description = "ID of project VPC"
  value       = aws_network_interface.foo.id
}