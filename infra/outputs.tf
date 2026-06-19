output "reports_bucket" {
    value = aws_s3_bucket.reports.id
}

output "budget_table" {
    value = aws_dynamodb_table.budget.name
}