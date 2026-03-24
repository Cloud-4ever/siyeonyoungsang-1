# ==========================================
# 1. Public 라우팅 (인터넷 게이트웨이와 연결)
# ==========================================
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "shopeasy-public-rt"
  }
}

# Public 서브넷들을 Public 라우팅 테이블에 연결
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "public_c" {
  subnet_id      = aws_subnet.public_c.id
  route_table_id = aws_route_table.public.id
}

# ==========================================
# 2. Private App 라우팅 (NAT 게이트웨이와 연결)
# ==========================================
resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "shopeasy-private-app-rt"
  }
}

# Private App 서브넷들을 연결
resource "aws_route_table_association" "private_app_a" {
  subnet_id      = aws_subnet.private_app_a.id
  route_table_id = aws_route_table.private_app.id
}
resource "aws_route_table_association" "private_app_c" {
  subnet_id      = aws_subnet.private_app_c.id
  route_table_id = aws_route_table.private_app.id
}

# ==========================================
# 3. Private DB 라우팅 (외부 통신 완전 차단, 격리용)
# ==========================================
resource "aws_route_table" "private_db" {
  vpc_id = aws_vpc.main.id
  # 인터넷으로 나가는 라우팅 규칙(0.0.0.0/0)을 아예 넣지 않아 완벽히 격리합니다.

  tags = {
    Name = "shopeasy-private-db-rt"
  }
}

# Private DB 서브넷들을 연결
resource "aws_route_table_association" "private_db_a" {
  subnet_id      = aws_subnet.private_db_a.id
  route_table_id = aws_route_table.private_db.id
}
resource "aws_route_table_association" "private_db_c" {
  subnet_id      = aws_subnet.private_db_c.id
  route_table_id = aws_route_table.private_db.id
}