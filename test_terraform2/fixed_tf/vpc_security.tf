# 1. 기본 보안 그룹(Default Security Group) 무력화
# 모든 인바운드/아웃바운드 규칙을 제거하여 의도치 않은 통신을 원천 차단합니다.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "shopeasy-default-sg-isolated"
  }
}

# 2. 기본 네트워크 ACL(Default Network ACL) 통제 (선택적 보안 강화)
# 서브넷 수준의 기본 방화벽도 코드로 명시하여 관리 상태에 둡니다.
resource "aws_default_network_acl" "default" {
  default_network_acl_id = aws_vpc.main.default_network_acl_id

  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "shopeasy-default-nacl"
  }
}