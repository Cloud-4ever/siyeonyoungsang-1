resource "aws_iam_role" "ec2_app_role" {
  name = "shopeasy-ec2-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_app_profile" {
  name = "shopeasy-ec2-app-profile"
  role = aws_iam_role.ec2_app_role.name
}