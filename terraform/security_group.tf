# 1. ALB 보안 그룹 (인터넷 공개 프런트엔드)
resource "aws_security_group" "alb" {
  name        = "shopeasy-alb-sg"
  description = "Allow HTTPS inbound traffic from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP to application subnets"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  tags = {
    Name = "shopeasy-alb-sg"
  }
}

# 2. EC2 App 보안 그룹 (애플리케이션 내부 통신 전용)
resource "aws_security_group" "app" {
  name        = "shopeasy-app-sg"
  description = "Allow traffic from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Traffic from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "MySQL to database subnets"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    description = "HTTPS outbound for updates and external APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "shopeasy-app-sg"
  }
}

# 3. RDS DB 보안 그룹 (데이터베이스 전용)
resource "aws_security_group" "db" {
  name        = "shopeasy-db-sg"
  description = "Allow traffic from App EC2 only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from App SG"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    description = "TLS within VPC only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  tags = {
    Name = "shopeasy-db-sg"
  }
}
