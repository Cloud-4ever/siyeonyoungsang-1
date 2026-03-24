resource "aws_dynamodb_table" "reviews" {
  name         = "shopeasy-reviews"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "review_id"

  attribute {
    name = "review_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.shared.arn
  }

  tags = {
    Name = "shopeasy-reviews"
  }
}
