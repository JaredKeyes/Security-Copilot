resource "aws_secretsmanager_secret" "anthropic" {
    name = var.anthropic_secret_name
    description = "Anthropic API key for the Security-Copilot demo Lambda"
}