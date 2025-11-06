provider "aws" {
  region = var.aws_region
}

# Provider for WAF (must be in us-east-1 for CloudFront)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# Data source for available AZs in the selected region
data "aws_availability_zones" "available" {
  state = "available"
}

# Data source to get current public IP
data "http" "current_ip" {
  url = "https://checkip.amazonaws.com"
}

# Local values for configuration
locals {
  # CloudFront prefix list is available in all AWS regions
  use_cloudfront_prefix_list = true
  
  # Fallback CIDR blocks if prefix list is not available
  cloudfront_fallback_cidrs = [
    "0.0.0.0/0"  # This should be replaced with actual CloudFront IP ranges if needed
  ]
  
  # Calculate /16 CIDR from current IP or override
  current_ip      = var.override_current_ip != "" ? var.override_current_ip : chomp(data.http.current_ip.response_body)
  current_ip_cidr = "${join(".", slice(split(".", local.current_ip), 0, 2))}.0.0/16"
}

# Data source for CloudFront managed prefix list
data "aws_ec2_managed_prefix_list" "cloudfront" {
  count = local.use_cloudfront_prefix_list ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

# Security group for Application Load Balancer
resource "aws_security_group" "litellm_alb_sg" {
  name_prefix = "litellm-alb-security-group-"
  description = "Allow inbound traffic for LiteLLM ALB"
  vpc_id      = aws_vpc.litellm_vpc.id

  # Allow HTTP/HTTPS traffic from CloudFront only
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "litellm-alb-sg"
  }
}

# VPC and networking resources
resource "aws_vpc" "litellm_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "litellm-vpc"
  }
}

# Public subnets for ECS tasks
resource "aws_subnet" "litellm_public_subnet_1" {
  vpc_id                  = aws_vpc.litellm_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "litellm-public-subnet-1"
  }
}

resource "aws_subnet" "litellm_public_subnet_2" {
  vpc_id                  = aws_vpc.litellm_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name = "litellm-public-subnet-2"
  }
}

# Private subnets for ECS tasks
resource "aws_subnet" "litellm_ecs_private_subnet_1" {
  vpc_id            = aws_vpc.litellm_vpc.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "litellm-ecs-private-subnet-1"
  }
}

resource "aws_subnet" "litellm_ecs_private_subnet_2" {
  vpc_id            = aws_vpc.litellm_vpc.id
  cidr_block        = "10.0.6.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "litellm-ecs-private-subnet-2"
  }
}

resource "aws_internet_gateway" "litellm_igw" {
  vpc_id = aws_vpc.litellm_vpc.id

  tags = {
    Name = "litellm-igw"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "litellm_nat_eip" {
  domain = "vpc"
  depends_on = [aws_internet_gateway.litellm_igw]

  tags = {
    Name = "litellm-nat-eip"
  }
}

# NAT Gateway in public subnet
resource "aws_nat_gateway" "litellm_nat" {
  allocation_id = aws_eip.litellm_nat_eip.id
  subnet_id     = aws_subnet.litellm_public_subnet_1.id
  depends_on    = [aws_internet_gateway.litellm_igw]

  tags = {
    Name = "litellm-nat-gateway"
  }
}

# Route table for public subnets (ALB)
resource "aws_route_table" "litellm_public_rt" {
  vpc_id = aws_vpc.litellm_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.litellm_igw.id
  }

  tags = {
    Name = "litellm-public-route-table"
  }
}

# Route table for private subnets (ECS)
resource "aws_route_table" "litellm_private_rt" {
  vpc_id = aws_vpc.litellm_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.litellm_nat.id
  }

  tags = {
    Name = "litellm-private-route-table"
  }
}

# Public subnet route table associations (for ALB)
resource "aws_route_table_association" "litellm_public_rta_1" {
  subnet_id      = aws_subnet.litellm_public_subnet_1.id
  route_table_id = aws_route_table.litellm_public_rt.id
}

resource "aws_route_table_association" "litellm_public_rta_2" {
  subnet_id      = aws_subnet.litellm_public_subnet_2.id
  route_table_id = aws_route_table.litellm_public_rt.id
}

# ECS private subnet route table associations
resource "aws_route_table_association" "litellm_ecs_private_rta_1" {
  subnet_id      = aws_subnet.litellm_ecs_private_subnet_1.id
  route_table_id = aws_route_table.litellm_private_rt.id
}

resource "aws_route_table_association" "litellm_ecs_private_rta_2" {
  subnet_id      = aws_subnet.litellm_ecs_private_subnet_2.id
  route_table_id = aws_route_table.litellm_private_rt.id
}

# Security group for ECS tasks (only allow traffic from ALB)
resource "aws_security_group" "litellm_ecs_sg" {
  name        = "litellm-ecs-security-group"
  description = "Allow inbound traffic for LiteLLM ECS tasks from ALB only"
  vpc_id      = aws_vpc.litellm_vpc.id

  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.litellm_alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "litellm-ecs-sg"
  }
}

# Random password for LiteLLM Master Key
resource "random_password" "master_key" {
  length  = 8
  special = false
  upper   = true
  lower   = true
  numeric = true
}

# Random ID for S3 bucket naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# AWS Secrets Manager secret for LiteLLM Master Key
resource "aws_secretsmanager_secret" "litellm_master_key" {
  name        = "litellm-master-key"
  description = "LiteLLM Master Key for API authentication"
  
  tags = {
    Name = "litellm-master-key"
  }
}

resource "aws_secretsmanager_secret_version" "litellm_master_key" {
  secret_id = aws_secretsmanager_secret.litellm_master_key.id
  secret_string = jsonencode({
    LITELLM_MASTER_KEY = "sk-${random_password.master_key.result}"
  })
}

# ECS Cluster
resource "aws_ecs_cluster" "litellm_cluster" {
  name = "litellm-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "litellm-cluster"
  }
}

# ECS Cluster Capacity Providers
resource "aws_ecs_cluster_capacity_providers" "litellm_cluster_capacity_providers" {
  cluster_name = aws_ecs_cluster.litellm_cluster.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "litellm-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# ECS Task Role (for runtime permissions)
resource "aws_iam_role" "ecs_task_role" {
  name = "litellm-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# IAM policy for Secrets Manager access
resource "aws_iam_role_policy" "ecs_secrets_policy" {
  name = "litellm-ecs-secrets-policy"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.litellm_master_key.arn
        ]
      }
    ]
  })
}

# Task Definition
resource "aws_ecs_task_definition" "litellm_task" {
  family                   = "litellm-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "litellm-container"
      image     = var.docker_image
      essential = true
      
      command = [
        "--port",
        "8000",
        "--host",
        "0.0.0.0"
      ]
      
      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]
      
      environment = [
        {
          name  = "UI_USERNAME"
          value = "admin"
        },
        {
          name  = "LITELLM_CONFIG_BUCKET_NAME"
          value = aws_s3_bucket.litellm_config_bucket.id
        },
        {
          name  = "LITELLM_CONFIG_BUCKET_OBJECT_KEY"
          value = "litellm_proxy_config.yaml"
        },
        {
          name  = "AWS_DEFAULT_REGION"
          value = var.aws_region
        },
        {
          name  = "PORT"
          value = tostring(var.container_port)
        },
        {
          name  = "LITELLM_LOG"
          value = "DEBUG"
        },
        {
          name  = "CONFIG_FILE_VERSION"
          value = aws_s3_object.litellm_config_file.etag
        }
      ]
      
      secrets = [
        {
          name      = "LITELLM_MASTER_KEY"
          valueFrom = "${aws_secretsmanager_secret.litellm_master_key.arn}:LITELLM_MASTER_KEY::"
        },
        {
          name      = "UI_PASSWORD"
          valueFrom = "${aws_secretsmanager_secret.litellm_master_key.arn}:LITELLM_MASTER_KEY::"
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/litellm-task"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "litellm"
          "awslogs-create-group"  = "true"
        }
      }
    }
  ])

  tags = {
    Name = "litellm-task-definition"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "litellm_logs" {
  name              = "/ecs/litellm-task"
  retention_in_days = 30

  tags = {
    Name = "litellm-logs"
  }
}

# ECS Service
resource "aws_ecs_service" "litellm_service" {
  name            = "litellm-service-v2"
  cluster         = aws_ecs_cluster.litellm_cluster.id
  task_definition = aws_ecs_task_definition.litellm_task.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.litellm_ecs_private_subnet_1.id, aws_subnet.litellm_ecs_private_subnet_2.id]
    security_groups  = [aws_security_group.litellm_ecs_sg.id]
    assign_public_ip = false  # No public IP needed in private subnet
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.litellm_tg.arn
    container_name   = "litellm-container"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.litellm_listener, aws_nat_gateway.litellm_nat]

  # Force service update when task definition changes (which includes config file changes)
  lifecycle {
    replace_triggered_by = [
      aws_ecs_task_definition.litellm_task
    ]
  }

  tags = {
    Name = "litellm-service-v2"
  }
}

# Application Load Balancer
resource "aws_lb" "litellm_lb" {
  name               = "litellm-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.litellm_alb_sg.id]
  subnets            = [aws_subnet.litellm_public_subnet_1.id, aws_subnet.litellm_public_subnet_2.id]
  idle_timeout       = 300

  tags = {
    Name = "litellm-lb"
  }
}

resource "aws_lb_target_group" "litellm_tg" {
  name        = "litellm-target-group"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.litellm_vpc.id
  target_type = "ip"

  health_check {
    enabled             = true
    interval            = 60
    path                = "/"  # Use root path for health check
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 30
    matcher             = "200"
  }

  tags = {
    Name = "litellm-target-group"
  }
}

resource "aws_lb_listener" "litellm_listener" {
  load_balancer_arn = aws_lb.litellm_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.litellm_tg.arn
  }
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "litellm_oac" {
  name                              = "litellm-oac"
  description                       = "Origin Access Control for LiteLLM"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront Cache Policy for API
resource "aws_cloudfront_cache_policy" "litellm_api_cache_policy" {
  name        = "litellm-api-cache-policy"
  comment     = "Cache policy for LiteLLM API endpoints"
  default_ttl = 0
  max_ttl     = 86400
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true

    query_strings_config {
      query_string_behavior = "all"
    }

    headers_config {
      header_behavior = "whitelist"
      headers {
        items = [
          "Authorization", 
          "Content-Type", 
          "User-Agent", 
          "Accept",
          "Origin",
          "Referer",
          "X-Requested-With",
          "Cache-Control"
        ]
      }
    }

    cookies_config {
      cookie_behavior = "all"
    }
  }
}

# CloudFront Origin Request Policy
resource "aws_cloudfront_origin_request_policy" "litellm_origin_request_policy" {
  name    = "litellm-origin-request-policy"
  comment = "Origin request policy for LiteLLM"

  query_strings_config {
    query_string_behavior = "all"
  }

  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "Content-Type",
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Origin",
        "Referer",
        "Host",
        "X-Requested-With",
        "Cache-Control"
      ]
    }
  }

  cookies_config {
    cookie_behavior = "all"
  }
}

# CloudFront Response Headers Policy
resource "aws_cloudfront_response_headers_policy" "litellm_security_headers" {
  name    = "litellm-security-headers"
  comment = "Security headers for LiteLLM"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = false
    }

    content_type_options {
      override = false
    }

    frame_options {
      frame_option = "DENY"
      override     = false
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = false
    }
  }

  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    access_control_max_age_sec = 86400
    origin_override            = false
  }
}

# WAF IP Set for allowed IPs
resource "aws_wafv2_ip_set" "allowed_ips" {
  count    = var.enable_waf ? 1 : 0
  provider = aws.us_east_1
  
  name               = "litellm-allowed-ips"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = [local.current_ip_cidr]

  tags = {
    Name = "litellm-allowed-ips"
  }
}

# WAF WebACL for CloudFront (must be in us-east-1)
resource "aws_wafv2_web_acl" "litellm_waf" {
  count    = var.enable_waf ? 1 : 0
  provider = aws.us_east_1
  
  name  = "litellm-cloudfront-waf"
  scope = "CLOUDFRONT"

  default_action {
    block {}
  }

  # IP allowlist rule
  rule {
    name     = "ip-allowlist"
    priority = 1

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allowed_ips[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPAllowlist"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "LiteLLMWAF"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "litellm-cloudfront-waf"
  }
}

# S3 Bucket for LiteLLM Configuration
resource "aws_s3_bucket" "litellm_config_bucket" {
  bucket = "kl-ecs-litellm-proxy-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "litellm-config-bucket"
    Environment = "production"
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "litellm_config_bucket_versioning" {
  bucket = aws_s3_bucket.litellm_config_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "litellm_config_bucket_encryption" {
  bucket = aws_s3_bucket.litellm_config_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "litellm_config_bucket_pab" {
  bucket = aws_s3_bucket.litellm_config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload LiteLLM Configuration File to S3
resource "aws_s3_object" "litellm_config_file" {
  bucket = aws_s3_bucket.litellm_config_bucket.id
  key    = "litellm_proxy_config.yaml"
  source = "${path.module}/litellm_proxy_config.yaml"
  etag   = filemd5("${path.module}/litellm_proxy_config.yaml")

  tags = {
    Name = "litellm-proxy-config"
  }
}

# IAM Policy for ECS to access S3 bucket
resource "aws_iam_policy" "ecs_s3_access_policy" {
  name        = "litellm-ecs-s3-access-policy"
  description = "Policy for ECS tasks to access LiteLLM config S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.litellm_config_bucket.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.litellm_config_bucket.arn
      }
    ]
  })
}

# Attach S3 access policy to ECS task execution role
resource "aws_iam_role_policy_attachment" "ecs_s3_access_policy_attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.ecs_s3_access_policy.arn
}

# Attach Bedrock full access policy to ECS task execution role
resource "aws_iam_role_policy_attachment" "ecs_bedrock_full_access_policy_attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
}

# Attach Bedrock full access policy to ECS task role (runtime permissions)
resource "aws_iam_role_policy_attachment" "ecs_task_bedrock_full_access_policy_attachment" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
}

# Attach S3 access policy to ECS task role (runtime permissions)
resource "aws_iam_role_policy_attachment" "ecs_task_s3_access_policy_attachment" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_s3_access_policy.arn
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "litellm_distribution" {
  origin {
    domain_name = aws_lb.litellm_lb.dns_name
    origin_id   = "litellm-alb-origin"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "http-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 5
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CloudFront distribution for LiteLLM"
  default_root_object = ""
  web_acl_id          = var.enable_waf ? aws_wafv2_web_acl.litellm_waf[0].arn : null

  # Default cache behavior for API endpoints
  default_cache_behavior {
    allowed_methods                = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods                 = ["GET", "HEAD", "OPTIONS"]
    target_origin_id               = "litellm-alb-origin"
    compress                       = true
    viewer_protocol_policy         = "redirect-to-https"
    
    cache_policy_id            = aws_cloudfront_cache_policy.litellm_api_cache_policy.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.litellm_origin_request_policy.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.litellm_security_headers.id
  }

  # Cache behavior for health check endpoint
  ordered_cache_behavior {
    path_pattern               = "/health*"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD", "OPTIONS"]
    target_origin_id           = "litellm-alb-origin"
    compress                   = true
    viewer_protocol_policy     = "redirect-to-https"
    
    cache_policy_id            = aws_cloudfront_cache_policy.litellm_api_cache_policy.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.litellm_origin_request_policy.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.litellm_security_headers.id
  }

  price_class = var.cloudfront_price_class

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "litellm-cloudfront"
  }
}
