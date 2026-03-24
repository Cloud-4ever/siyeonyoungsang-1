resource "aws_dynamodb_table" "reviews" {
  name           = "shopeasy-reviews"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "review_id"

  attribute {
    name = "review_id"
    type = "S"
  }
}