# S3 Configuration Outputs
output "s3_config_bucket_name" {
  description = "Name of the S3 bucket storing LiteLLM configuration"
  value       = aws_s3_bucket.litellm_config_bucket.id
}

output "s3_config_bucket_arn" {
  description = "ARN of the S3 bucket storing LiteLLM configuration"
  value       = aws_s3_bucket.litellm_config_bucket.arn
}

output "s3_config_object_key" {
  description = "Object key of the LiteLLM configuration file in S3"
  value       = aws_s3_object.litellm_config_file.key
}

output "s3_config_object_url" {
  description = "S3 URL of the LiteLLM configuration file"
  value       = "s3://${aws_s3_bucket.litellm_config_bucket.id}/${aws_s3_object.litellm_config_file.key}"
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.litellm_lb.dns_name
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.litellm_cluster.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.litellm_service.name
}

output "task_definition_family" {
  description = "Family of the task definition"
  value       = aws_ecs_task_definition.litellm_task.family
}

output "ecs_security_group_id" {
  description = "ID of the ECS security group"
  value       = aws_security_group.litellm_ecs_sg.id
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.litellm_vpc.id
}

output "application_url" {
  description = "Primary URL to access the LiteLLM application (via CloudFront)"
  value       = "https://${aws_cloudfront_distribution.litellm_distribution.domain_name}"
}

# CloudFront Outputs
output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.litellm_distribution.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.litellm_distribution.domain_name
}

output "cloudfront_hosted_zone_id" {
  description = "CloudFront distribution hosted zone ID"
  value       = aws_cloudfront_distribution.litellm_distribution.hosted_zone_id
}

output "application_url_cloudfront" {
  description = "URL to access the LiteLLM application via CloudFront"
  value       = "https://${aws_cloudfront_distribution.litellm_distribution.domain_name}"
}

output "application_url_direct" {
  description = "Direct URL to access the LiteLLM application via Load Balancer"
  value       = "http://${aws_lb.litellm_lb.dns_name}"
}

# NAT Gateway and Networking Outputs
output "nat_gateway_id" {
  description = "ID of the NAT Gateway"
  value       = aws_nat_gateway.litellm_nat.id
}

output "nat_gateway_public_ip" {
  description = "Public IP of the NAT Gateway"
  value       = aws_eip.litellm_nat_eip.public_ip
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (ALB)"
  value       = [aws_subnet.litellm_public_subnet_1.id, aws_subnet.litellm_public_subnet_2.id]
}

output "ecs_private_subnet_ids" {
  description = "IDs of the ECS private subnets"
  value       = [aws_subnet.litellm_ecs_private_subnet_1.id, aws_subnet.litellm_ecs_private_subnet_2.id]
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.litellm_alb_sg.id
}

# UI Credentials
output "ui_username" {
  description = "Username for LiteLLM Web UI"
  value       = "admin"
}

output "ui_password" {
  description = "Password for LiteLLM Web UI (same as LITELLM_MASTER_KEY)"
  value       = "sk-${random_password.master_key.result}"
  sensitive   = true
}

output "litellm_master_key" {
  description = "LiteLLM Master Key for API authentication"
  value       = "sk-${random_password.master_key.result}"
  sensitive   = true
}

output "litellm_master_key_secret_arn" {
  description = "ARN of the Secrets Manager secret containing LiteLLM Master Key"
  value       = aws_secretsmanager_secret.litellm_master_key.arn
}

# WAF Outputs
output "allowed_ip_cidr" {
  description = "Your current IP's /16 CIDR range allowed by WAF"
  value       = var.enable_waf ? local.current_ip_cidr : "WAF not enabled"
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = var.enable_waf ? aws_wafv2_web_acl.litellm_waf[0].id : null
}
