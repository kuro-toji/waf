# Terraform configuration for AWS
# Deploys WAF with ALB, EC2 instances, and Redis (ElastiCache)

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "waf-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC for WAF deployment
resource "aws_vpc" "waf_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "waf-vpc-${var.environment}"
  }
}

# Public subnets for ALB
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.waf_vpc.id
  cidr_block              = var.public_subnet_1
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "waf-public-${var.environment}-1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.waf_vpc.id
  cidr_block              = var.public_subnet_2
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "waf-public-${var.environment}-2"
  }
}

# Private subnets for WAF instances
resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.waf_vpc.id
  cidr_block        = var.private_subnet_1
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "waf-private-${var.environment}-1"
  }
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.waf_vpc.id
  cidr_block        = var.private_subnet_2
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "waf-private-${var.environment}-2"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "waf_igw" {
  vpc_id = aws_vpc.waf_vpc.id

  tags = {
    Name = "waf-igw-${var.environment}"
  }
}

# Elastic Load Balancer (Application Load Balancer)
resource "aws_lb" "waf_alb" {
  name               = "waf-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  enable_deletion_protection = false

  tags = {
    Name = "waf-alb-${var.environment}"
  }
}

# Security Groups
resource "aws_security_group" "alb_sg" {
  name        = "waf-alb-sg-${var.environment}"
  description = "Security group for WAF ALB"
  vpc_id      = aws_vpc.waf_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "waf-alb-sg-${var.environment}"
  }
}

resource "aws_security_group" "waf_instances" {
  name        = "waf-instances-sg-${var.environment}"
  description = "Security group for WAF EC2 instances"
  vpc_id      = aws_vpc.waf_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "waf-instances-sg-${var.environment}"
  }
}

# Launch Template for WAF instances
resource "aws_launch_template" "waf_lt" {
  name_prefix   = "waf-"
  image_id      = var.ami_id
  instance_type = var.instance_type

  key_name = var.key_pair

  vpc_security_group_ids = [aws_security_group.waf_instances.id]

  user_data = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              amazon-linux-extras install docker
              service docker start
              systemctl enable docker
              docker run -d --restart unless-stopped \
                -p 8080:8080 -p 9090:9090 \
                -v /opt/waf/config:/app/config:ro \
                -v /opt/waf/rules:/app/rules:ro \
                ${var.waf_image}:latest
              EOF

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "waf-instance-${var.environment}"
    }
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "waf_asg" {
  name                = "waf-asg-${var.environment}"
  vpc_zone_identifier = [aws_subnet.private_1.id, aws_subnet.private_2.id]
  desired_capacity    = var.desired_capacity
  min_size            = var.min_size
  max_size            = var.max_size

  launch_template {
    id      = aws_launch_template.waf_lt.id
    version = "$Latest"
  }

  health_check_type = "ELB"
  health_check_grace_period = 300

  tag {
    key                 = "Name"
    value               = "waf-asg-${var.environment}"
    propagate_at_launch = true
  }
}

# Target Group for ALB
resource "aws_lb_target_group" "waf_tg" {
  name     = "waf-tg-${var.environment}"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.waf_vpc.id

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

# ALB Listener (HTTPS)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.waf_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.waf_tg.arn
  }
}

# ElastiCache Redis for rate limiting
resource "aws_elasticache_subnet_group" "waf_redis" {
  name       = "waf-redis-subnet-${var.environment}"
  subnet_ids = [aws_subnet.private_1.id, aws_subnet.private_2.id]
}

resource "aws_elasticache_security_group" "waf_redis_sg" {
  name                 = "waf-redis-sg-${var.environment}"
  description          = "Security group for WAF Redis"
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.waf_instances.id]
  }
}

resource "aws_elasticache_cluster" "waf_redis" {
  cluster_id           = "waf-redis-${var.environment}"
  engine               = "redis"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  security_group_ids   = [aws_elasticache_security_group.waf_redis_sg.id]
  subnet_group_name    = aws_elasticache_subnet_group.waf_redis.name
}

# IAM Role for WAF instances
resource "aws_iam_role" "waf_role" {
  name = "waf-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "waf_cloudwatch" {
  role       = aws_iam_role.waf_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/ec2/waf-${var.environment}"
  retention_in_days = 7

  tags = {
    Name = "waf-logs-${var.environment}"
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_1" {
  description = "Public subnet 1 CIDR"
  type        = string
  default     = "10.0.1.0/24"
}

variable "public_subnet_2" {
  description = "Public subnet 2 CIDR"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_subnet_1" {
  description = "Private subnet 1 CIDR"
  type        = string
  default     = "10.0.10.0/24"
}

variable "private_subnet_2" {
  description = "Private subnet 2 CIDR"
  type        = string
  default     = "10.0.11.0/24"
}

variable "ami_id" {
  description = "Amazon Machine Image ID for WAF instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0" # Amazon Linux 2023
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "key_pair" {
  description = "SSH key pair name"
  type        = string
  default     = "waf-key"
}

variable "waf_image" {
  description = "WAF Docker image URL"
  type        = string
  default     = "ghcr.io/username/waf:latest"
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS"
  type        = string
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "desired_capacity" {
  description = "Desired ASG capacity"
  type        = number
  default     = 2
}

variable "min_size" {
  description = "Minimum ASG size"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Maximum ASG size"
  type        = number
  default     = 5
}

# Outputs
output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.waf_alb.dns_name
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = aws_elasticache_cluster.waf_redis.cache_nodes[0].address
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.waf_vpc.id
}