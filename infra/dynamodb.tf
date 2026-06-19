resource "aws_dynamodb_table" "budget" {
    name = var.budget_table_name
    billing_mode = "PAY_PER_REQUEST"
    hash_key = "day"

    attribute {
        name = "day"
        type = "S"
    }
}