resource "aws_s3_bucket" "images" {
  bucket = "shopeasy-image-bucket-c4-easyshop-review-image"
}

resource "aws_s3_bucket" "static_assets" {
  bucket = "shopeasy-static-bucket-c4-easyshop-assets"
}

resource "aws_s3_bucket_public_access_block" "images" {
  bucket = aws_s3_bucket.images.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "images" {
  bucket = aws_s3_bucket.images.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.shared.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.shared.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "images" {
  bucket = aws_s3_bucket.images.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "images" {
  bucket = aws_s3_bucket.images.id

  rule {
    id     = "default-lifecycle"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  rule {
    id     = "default-lifecycle"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "images" {
  bucket = aws_s3_bucket.images.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.images.arn,
          "${aws_s3_bucket.images.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.static_assets.arn,
          "${aws_s3_bucket.static_assets.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_logging" "images" {
  bucket        = aws_s3_bucket.images.id
  target_bucket = aws_s3_bucket.alb_logs.id
  target_prefix = "images/"
}

resource "aws_s3_bucket_logging" "static_assets" {
  bucket        = aws_s3_bucket.static_assets.id
  target_bucket = aws_s3_bucket.alb_logs.id
  target_prefix = "static-assets/"
}

resource "aws_s3_bucket_notification" "images" {
  bucket = aws_s3_bucket.images.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket" "alb_logs_replica" {
  provider      = aws.secondary
  bucket        = "shopeasy-alb-logs-replica-1234567890"
  force_destroy = true

  tags = {
    Name = "shopeasy-alb-logs-replica"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.alb_logs_replica.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "images_replica" {
  provider      = aws.secondary
  bucket        = "shopeasy-images-replica-1234567890"
  force_destroy = true

  tags = {
    Name = "shopeasy-images-replica"
  }
}

resource "aws_s3_bucket_public_access_block" "images_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.images_replica.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "static_assets_replica" {
  provider      = aws.secondary
  bucket        = "shopeasy-static-assets-replica-1234567890"
  force_destroy = true

  tags = {
    Name = "shopeasy-static-assets-replica"
  }
}

resource "aws_s3_bucket_public_access_block" "static_assets_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.static_assets_replica.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.alb_logs_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "images_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.images_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "static_assets_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.static_assets_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "alb_logs_replica" {
  provider      = aws.secondary
  bucket        = aws_s3_bucket.alb_logs_replica.id
  target_bucket = aws_s3_bucket.alb_logs_replica.id
  target_prefix = "replica-audit/"
}

resource "aws_s3_bucket_logging" "images_replica" {
  provider      = aws.secondary
  bucket        = aws_s3_bucket.images_replica.id
  target_bucket = aws_s3_bucket.alb_logs_replica.id
  target_prefix = "images-replica/"
}

resource "aws_s3_bucket_logging" "static_assets_replica" {
  provider      = aws.secondary
  bucket        = aws_s3_bucket.static_assets_replica.id
  target_bucket = aws_s3_bucket.alb_logs_replica.id
  target_prefix = "static-assets-replica/"
}

resource "aws_sns_topic" "s3_events_secondary" {
  provider          = aws.secondary
  name              = "shopeasy-s3-events-secondary"
  kms_master_key_id = aws_kms_key.shared.arn
}

resource "aws_sns_topic_policy" "s3_events_secondary" {
  provider = aws.secondary
  arn      = aws_sns_topic.s3_events_secondary.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3PublishSecondary"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.s3_events_secondary.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = [
              aws_s3_bucket.alb_logs_replica.arn,
              aws_s3_bucket.images_replica.arn,
              aws_s3_bucket.static_assets_replica.arn
            ]
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "alb_logs_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.alb_logs_replica.id

  topic {
    topic_arn = aws_sns_topic.s3_events_secondary.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events_secondary]
}

resource "aws_s3_bucket_notification" "images_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.images_replica.id

  topic {
    topic_arn = aws_sns_topic.s3_events_secondary.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events_secondary]
}

resource "aws_s3_bucket_notification" "static_assets_replica" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.static_assets_replica.id

  topic {
    topic_arn = aws_sns_topic.s3_events_secondary.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events_secondary]
}

resource "aws_s3_bucket_replication_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  role   = aws_iam_role.s3_replication.arn

  depends_on = [
    aws_s3_bucket_versioning.alb_logs,
    aws_s3_bucket_versioning.alb_logs_replica
  ]

  rule {
    id     = "replicate-alb-logs"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.alb_logs_replica.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "images" {
  bucket = aws_s3_bucket.images.id
  role   = aws_iam_role.s3_replication.arn

  depends_on = [
    aws_s3_bucket_versioning.images,
    aws_s3_bucket_versioning.images_replica
  ]

  rule {
    id     = "replicate-images"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.images_replica.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id
  role   = aws_iam_role.s3_replication.arn

  depends_on = [
    aws_s3_bucket_versioning.static_assets,
    aws_s3_bucket_versioning.static_assets_replica
  ]

  rule {
    id     = "replicate-static-assets"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.static_assets_replica.arn
      storage_class = "STANDARD"
    }
  }
}
