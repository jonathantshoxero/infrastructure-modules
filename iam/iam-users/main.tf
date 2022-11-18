resource "aws_iam_user" "lb" {
  name = var.iam_user
  tags = {
    use_case = var.tag_use_case
  }
}