# 1. Internet Gateway (Public Subnet 외부 통신용)
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "shopeasy-igw"
  }
}

# 2. NAT Gateway용 고정 IP (EIP)
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "shopeasy-nat-eip"
  }
}

# 3. NAT Gateway (Private Subnet의 외부 인터넷 접속용)
# 주의: NAT Gateway는 반드시 Public Subnet에 위치해야 합니다.
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id

  tags = {
    Name = "shopeasy-nat-gateway"
  }

  # 인터넷 게이트웨이가 먼저 생성되어야 NAT 게이트웨이가 정상 작동합니다.
  depends_on = [aws_internet_gateway.main]
}