

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_replica" {
  bucket = aws_s3_bucket.alb_logs_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.rds.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "images_replica" {
  bucket = aws_s3_bucket.images_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.rds.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "static_assets_replica" {
  bucket = aws_s3_bucket.static_assets_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.rds.arn
    }
  }
}
