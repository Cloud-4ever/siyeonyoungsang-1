# 1. DB ?쒕툕??洹몃９ (Private DB ?쒕툕??2媛?臾띔린)
resource "aws_db_subnet_group" "main" {
  name       = "shopeasy-db-subnet-group"
  subnet_ids = [aws_subnet.private_db_a.id, aws_subnet.private_db_c.id]

  tags = {
    Name = "shopeasy-db-subnet-group"
  }
}

# 2. KMS ??(RDS ?뷀샇?붿슜)
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowRDSServiceUse"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "shopeasy-rds-kms-key"
  }
}

resource "aws_kms_key" "shared" {
  description             = "Shared KMS key for app data encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "shopeasy-shared-kms-key"
  }
}

# 3. RDS ?몄뒪?댁뒪 (MySQL)
resource "aws_db_instance" "main" {
  identifier        = "shopeasy-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "shopeasydb"
  username = "admin"
  password = "password1234!" # ?뚯뒪?몄슜

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  multi_az                            = true
  publicly_accessible                 = false
  skip_final_snapshot                 = true
  deletion_protection                 = true
  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["error", "general", "slowquery"]
  monitoring_interval                 = 60
  monitoring_role_arn                 = aws_iam_role.rds_monitoring.arn

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  tags = {
    Name = "shopeasy-rds"
  }
}
