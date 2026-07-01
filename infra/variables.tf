variable "aws_profile" {
    description = "Named AWS SSO profile"
    type = string
    default = "test"
}

variable "aws_region" {
    type = string
    default = "us-east-1"
}

variable "demo_account_id" {
    description = "Demo account ID - provider refuses to apply elsewhere"
    type = string
}

variable "reports_bucket_name" {
    description = "Globally-unique S3 bucket for precomputed reports + frontend assets"
    type = string
}

variable "budget_table_name" {
    type = string
    default = "demo-budget"
}

variable "lambda_function_name" {
    type = string
    default = "security-copilot-api"
}

variable "ecr_repo_name" {
    type = string
    default = "security-copilot"
}

variable "image_tag" {
    description = "Tag of the serving image pushed to ECR"
    type = string
    default = "dev"
}

variable "anthropic_secret_name" {
    description = "Secrets Manager secret holding the Anthropic API key (value set out-of-band)"
    type = string
    default = "security-copilot/anthropic-api-key"
}

variable "daily_token_cap" {
    type = number
    default = 2000000
}

variable "cors_allow_origins" {
    description = "Allowed CORS origins; lock to the portfolio/demo domain in prod"
    type = list(string)
    default = [ "*" ]
}

variable "spa_bucket_name" {
    type = string
}

variable "spa_domain_name" {
    type = string
}