resource "aws_lambda_function" "api" {
    function_name = var.lambda_function_name
    role = aws_iam_role.lambda.arn
    package_type = "Image"
    image_uri = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"

    timeout = 30
    memory_size = 3008

    environment {
        variables = {
            REPORTS_BUCKET = aws_s3_bucket.reports.id
            BUDGET_TABLE = aws_dynamodb_table.budget.name
            ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.anthropic.arn
            DAILY_TOKEN_CAP = tostring(var.daily_token_cap)
        }
    }
}