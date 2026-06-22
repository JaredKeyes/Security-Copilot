output "reports_bucket" {
    value = aws_s3_bucket.reports.id
}

output "budget_table" {
    value = aws_dynamodb_table.budget.name
}

output "api_endpoint" {
    value = aws_apigatewayv2_stage.default.invoke_url
}

output "ecr_repository_url" {
    value = aws_ecr_repository.app.repository_url
}

output "lambda_function_name" {
    value = aws_lambda_function.api.function_name
}

output "anthropic_secret_arn" {
    value = aws_secretsmanager_secret.anthropic.arn
}