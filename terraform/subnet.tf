# ==========================================
# 1. Public Subnets (인터넷 공개 서브넷 - ALB, NAT 게이트웨이)
# ==========================================
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "shopeasy-public-subnet-2a"
  }
}

resource "aws_subnet" "public_c" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "shopeasy-public-subnet-2c"
  }
}

# ==========================================
# 2. Private Subnets - App (애플리케이션 내부 서브넷 - EC2 API 서버)
# ==========================================
resource "aws_subnet" "private_app_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.11.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "shopeasy-private-app-subnet-2a"
  }
}

resource "aws_subnet" "private_app_c" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.12.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "shopeasy-private-app-subnet-2c"
  }
}

# ==========================================
# 3. Private Subnets - DB (데이터베이스 전용 서브넷 - RDS 배치용)
# ==========================================
resource "aws_subnet" "private_db_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.21.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "shopeasy-private-db-subnet-2a"
  }
}

resource "aws_subnet" "private_db_c" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.22.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "shopeasy-private-db-subnet-2c"
  }
}
