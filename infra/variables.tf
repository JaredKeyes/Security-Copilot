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