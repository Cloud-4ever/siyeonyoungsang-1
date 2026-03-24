

resource "aws_s3_bucket_acl" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "alb_logs_replica" {
  bucket = aws_s3_bucket.alb_logs_replica.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "images" {
  bucket = aws_s3_bucket.images.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "images_replica" {
  bucket = aws_s3_bucket.images_replica.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "static_assets_replica" {
  bucket = aws_s3_bucket.static_assets_replica.id
  acl    = "private"
}
