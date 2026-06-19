terraform {
    required_version = ">= 1.5"
    required_providers {
      aws = {
        source = "hashicorp/aws"
        version = "~> 5.0"
      }
    }
}

provider "aws" {
    region = var.aws_region
    profile = var.aws_profile
    allowed_account_ids = [var.demo_account_id]
}

terraform {
    backend "s3" {
        bucket = "security-copilot-tfstate-jaredk"
        key = "security-copilot/terraform.tfstate"
        region = "us-east-1"
        profile = "test"
        encrypt = true
        use_lockfile = true
    }
}