# C4-Finder 자동 조치(3.9): ALB 액세스 로그 수신용 버킷
data "aws_caller_identity" "c4f_alb_logs_main" {}

data "aws_iam_policy_document" "c4f_alb_logs_main" {
  statement {
    sid    = "AllowELBLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.c4f_alb_logs_main.arn}/AWSLogs/${data.aws_caller_identity.c4f_alb_logs_main.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket" "c4f_alb_logs_main" {
  bucket_prefix = "c4f-alb-logs-main-"
}

resource "aws_s3_bucket_public_access_block" "c4f_alb_logs_main" {
  bucket = aws_s3_bucket.c4f_alb_logs_main.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "c4f_alb_logs_main" {
  bucket = aws_s3_bucket.c4f_alb_logs_main.id
  policy = data.aws_iam_policy_document.c4f_alb_logs_main.json
}
