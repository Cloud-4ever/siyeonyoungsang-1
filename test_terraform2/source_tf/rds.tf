# 1. DB 서브넷 그룹 (Private DB 서브넷 2개 묶기)
resource "aws_db_subnet_group" "main" {
  name       = "shopeasy-db-subnet-group"
  subnet_ids = [aws_subnet.private_db_a.id, aws_subnet.private_db_c.id]

  tags = {
    Name = "shopeasy-db-subnet-group"
  }
}

# 2. KMS 키 (RDS 암호화용)
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7

  tags = {
    Name = "shopeasy-rds-kms-key"
  }
}

# 3. RDS 인스턴스 (MySQL)
resource "aws_db_instance" "main" {
  identifier             = "shopeasy-rds"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20

  db_name                = "shopeasydb"
  username               = "admin"
  password               = "password1234!"  # 테스트용

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  multi_az               = false
  publicly_accessible    = false
  skip_final_snapshot    = true

  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds.arn

  tags = {
    Name = "shopeasy-rds"
  }
}