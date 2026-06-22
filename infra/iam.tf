data "aws_iam_policy_document" "lambda_assume" {
    statement {
        actions = ["sts:AssumeRole"]
        principals {
            type = "Service"
            identifiers = ["lambda.amazonaws.com"]
        }
    }
}

resource "aws_iam_role" "lambda" {
    name = "${var.lambda_function_name}-role"
    assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
    role = aws_iam_role.lambda.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_app" {
    statement {
      sid = "ReadReports"
      actions = ["s3:GetObject"]
      resources = ["${aws_s3_bucket.reports.arn}/*"]
    }
    statement {
        sid = "BudgetCounter"
        actions = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        resources = [aws_dynamodb_table.budget.arn]
    }
    statement {
      sid = "ReadAnthropicKey"
      actions = ["secretsmanager:GetSecretValue"]
      resources = [aws_secretsmanager_secret.anthropic.arn]
    }
}

resource "aws_iam_role_policy" "lambda_app" {
    name = "${var.lambda_function_name}-app"
    role = aws_iam_role.lambda.id
    policy = data.aws_iam_policy_document.lambda_app.json
}