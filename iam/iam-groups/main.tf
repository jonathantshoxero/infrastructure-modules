resource "aws_iam_group" "developers" {
  name = var.iam_group_name
  path = "/"
}