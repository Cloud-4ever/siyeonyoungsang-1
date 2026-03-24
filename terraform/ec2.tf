# 1. 理쒖떊 Amazon Linux 2023 AMI ?먮룞 寃??
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# 2. EC2 #1 (媛?⑹쁺??A??Private App ?쒕툕?룹뿉 諛곗튂)
resource "aws_instance" "app_a" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_app_a.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_app_profile.name
  monitoring             = true
  ebs_optimized          = true

  root_block_device {
    encrypted             = true
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "shopeasy-app-ec2-a"
  }
}

# 3. EC2 #2 (媛?⑹쁺??C??Private App ?쒕툕?룹뿉 諛곗튂)
resource "aws_instance" "app_c" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_app_c.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_app_profile.name
  monitoring             = true
  ebs_optimized          = true

  root_block_device {
    encrypted             = true
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "shopeasy-app-ec2-c"
  }
}

# 4. EC2 ?몄뒪?댁뒪?ㅼ쓣 ALB ?寃?洹몃９???곌껐
resource "aws_lb_target_group_attachment" "app_a" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app_a.id
  port             = 8080
}

resource "aws_lb_target_group_attachment" "app_c" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app_c.id
  port             = 8080
}
