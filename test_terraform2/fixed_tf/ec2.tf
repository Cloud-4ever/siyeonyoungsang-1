# 1. 최신 Amazon Linux 2023 AMI 자동 검색
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# 2. EC2 #1 (가용영역 A의 Private App 서브넷에 배치)
resource "aws_instance" "app_a" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_app_a.id
  vpc_security_group_ids = [aws_security_group.app.id]

  root_block_device {
    encrypted             = true
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "shopeasy-app-ec2-a"
  }
}

# 3. EC2 #2 (가용영역 C의 Private App 서브넷에 배치)
resource "aws_instance" "app_c" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_app_c.id
  vpc_security_group_ids = [aws_security_group.app.id]

  root_block_device {
    encrypted             = true
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "shopeasy-app-ec2-c"
  }
}

# 4. EC2 인스턴스들을 ALB 타겟 그룹에 연결
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