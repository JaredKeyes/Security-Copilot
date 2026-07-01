# --- Private SPA bucket ---
resource "aws_s3_bucket" "spa" {
  bucket = var.spa_bucket_name
}

resource "aws_s3_bucket_public_access_block" "spa" {
  bucket                  = aws_s3_bucket.spa.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- CloudFront Origin Access Control ---
resource "aws_cloudfront_origin_access_control" "spa" {
  name                              = "${var.spa_bucket_name}-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# --- ACM cert (CloudFront requires us-east-1; stack already is) ---
resource "aws_acm_certificate" "spa" {
  domain_name       = var.spa_domain_name
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

# --- Delegated hosted zone for demo.jaredkeyes.site (apex lives in prod acct) ---
resource "aws_route53_zone" "demo" {
  name = var.spa_domain_name
}

resource "aws_route53_record" "acm_validation" {
  for_each = { for o in aws_acm_certificate.spa.domain_validation_options : o.domain_name => o }
  zone_id  = aws_route53_zone.demo.zone_id
  name     = each.value.resource_record_name
  type     = each.value.resource_record_type
  records  = [each.value.resource_record_value]
  ttl      = 300
}

resource "aws_acm_certificate_validation" "spa" {
  certificate_arn         = aws_acm_certificate.spa.arn
  validation_record_fqdns = [for r in aws_route53_record.acm_validation : r.fqdn]
}

# --- Security headers ---
resource "aws_cloudfront_response_headers_policy" "spa" {
  name = "${var.spa_bucket_name}-sec-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    content_security_policy {
      content_security_policy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ${aws_apigatewayv2_api.http.api_endpoint}"
      override                = true
    }
  }
}

# --- Distribution ---
resource "aws_cloudfront_distribution" "spa" {
  enabled             = true
  default_root_object = "index.html"
  aliases             = [var.spa_domain_name]
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.spa.bucket_regional_domain_name
    origin_id                = "spa-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.spa.id
  }

  default_cache_behavior {
    target_origin_id           = "spa-s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    response_headers_policy_id = aws_cloudfront_response_headers_policy.spa.id
    cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6" # Managed-CachingOptimized
  }

  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.spa.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# --- Bucket policy: only this distribution may read (OAC) ---
data "aws_iam_policy_document" "spa" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.spa.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.spa.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "spa" {
  bucket = aws_s3_bucket.spa.id
  policy = data.aws_iam_policy_document.spa.json
}

# --- Alias records demo.jaredkeyes.site -> CloudFront ---
resource "aws_route53_record" "spa_a" {
  zone_id = aws_route53_zone.demo.zone_id
  name    = var.spa_domain_name
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.spa.domain_name
    zone_id                = aws_cloudfront_distribution.spa.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "spa_aaaa" {
  zone_id = aws_route53_zone.demo.zone_id
  name    = var.spa_domain_name
  type    = "AAAA"
  alias {
    name                   = aws_cloudfront_distribution.spa.domain_name
    zone_id                = aws_cloudfront_distribution.spa.hosted_zone_id
    evaluate_target_health = false
  }
}

output "spa_bucket_name" {
  value = aws_s3_bucket.spa.bucket
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.spa.domain_name
}

output "demo_zone_nameservers" {
  value = aws_route53_zone.demo.name_servers
}