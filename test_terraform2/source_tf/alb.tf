# ================================
# 0. ALB Access Log 저장용 S3 버킷
# ================================
resource "aws_s3_bucket" "alb_logs" {
  bucket = "shopeasy-alb-logs-1234567890"
  force_destroy = true

  tags = {
    Name = "shopeasy-alb-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# ALB 로그 전달을 위한 버킷 정책
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "logdelivery.elasticloadbalancing.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/*"
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "logdelivery.elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# ================================
# 1. ACM 인증서
# ================================
# 실사용 도메인이 있어야 함
resource "aws_acm_certificate" "main" {
  domain_name       = "example.com"   # <- 본인 도메인으로 변경
  validation_method = "DNS"

  tags = {
    Name = "shopeasy-acm-cert"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ================================
# 2. ALB (Application Load Balancer)
# ================================
resource "aws_lb" "main" {
  name               = "shopeasy-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_c.id]

  # 점검 항목 대응
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb"
    enabled = true
  }

  tags = {
    Name = "shopeasy-alb"
  }
}

# ================================
# 3. 타겟 그룹
# ================================
resource "aws_lb_target_group" "app" {
  name     = "shopeasy-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 30
  }

  tags = {
    Name = "shopeasy-tg"
  }
}

# ================================
# 4. HTTP 리스너 -> HTTPS 리다이렉트
# ================================
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ================================
# 5. HTTPS 리스너
# ================================
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ================================
# 6. WAF Web ACL
# ================================
resource "aws_wafv2_web_acl" "main" {
  name  = "shopeasy-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "shopeasyWebAcl"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "shopeasy-web-acl"
  }
}

# ================================
# 7. WAF와 ALB 연결
# ================================
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}