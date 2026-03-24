# 1. ALB 보안 그룹 (인터넷 트래픽 진입점)
resource "aws_security_group" "alb" {
  name        = "shopeasy-alb-sg"
  description = "Allow HTTP inbound traffic from internet"
  vpc_id      = aws_vpc.main.id

  # 인바운드: 인터넷(0.0.0.0/0)에서 80 포트로 들어오는 트래픽 허용
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 아웃바운드: 외부로 나가는 모든 트래픽 허용
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "shopeasy-alb-sg"
  }
}

# 2. EC2 App 보안 그룹 (애플리케이션 서버)
resource "aws_security_group" "app" {
  name        = "shopeasy-app-sg"
  description = "Allow traffic from ALB only"
  vpc_id      = aws_vpc.main.id

  # 인바운드: ALB 보안 그룹에서 들어오는 트래픽만 허용 (예: 8080 포트)
  ingress {
    description     = "Traffic from ALB"
    from_port       = 8080 
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id] # ALB 보안 그룹 ID 참조
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "shopeasy-app-sg"
  }
}

# 3. RDS DB 보안 그룹 (데이터베이스)
resource "aws_security_group" "db" {
  name        = "shopeasy-db-sg"
  description = "Allow traffic from App EC2 only"
  vpc_id      = aws_vpc.main.id

  # 인바운드: App 보안 그룹에서 들어오는 트래픽만 허용 (MySQL 기본 3306 포트 기준)
  ingress {
    description     = "MySQL from App SG"
    from_port       = 3306 
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id] # App 보안 그룹 ID 참조
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "shopeasy-db-sg"
  }
}