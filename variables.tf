variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "ap-northeast-1"
}

variable "app_name" {
  description = "Name of the application"
  type        = string
  default     = "litellm"
}

variable "container_port" {
  description = "Port exposed by the docker image"
  type        = number
  default     = 8000
}

variable "cpu" {
  description = "Fargate instance CPU units to provision"
  type        = string
  default     = "512"
}

variable "memory" {
  description = "Fargate instance memory to provision (in MiB)"
  type        = string
  default     = "1024"
}

variable "desired_count" {
  description = "Number of ECS tasks to run"
  type        = number
  default     = 1
}

variable "docker_image" {
  description = "Docker image to run in the ECS cluster"
  type        = string
  default     = "litellm/litellm:v1.79.0-stable"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# CloudFront Variables
variable "cloudfront_price_class" {
  description = "CloudFront distribution price class"
  type        = string
  default     = "PriceClass_100"
  validation {
    condition = contains([
      "PriceClass_All",
      "PriceClass_200",
      "PriceClass_100"
    ], var.cloudfront_price_class)
    error_message = "CloudFront price class must be PriceClass_All, PriceClass_200, or PriceClass_100."
  }
}

variable "enable_cloudfront_logging" {
  description = "Enable CloudFront access logging"
  type        = bool
  default     = false
}

# NAT Gateway Variables
variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet internet access"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets (cost optimization)"
  type        = bool
  default     = true
}

# WAF Variables
variable "enable_waf" {
  description = "Enable WAF for CloudFront distribution"
  type        = bool
  default     = true
}

variable "override_current_ip" {
  description = "Override the auto-detected current IP with a specific IP address. If set, this IP's /16 CIDR will be used instead of auto-detection."
  type        = string
  default     = ""
}
