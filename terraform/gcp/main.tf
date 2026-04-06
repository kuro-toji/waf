# Terraform configuration for GCP
# Deploys WAF with Cloud Load Balancing, GCE instances, and Memorystore Redis

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "waf-terraform-state"
    prefix = "prod"
  }
}

provider "google" {
  project = var.project_id
  region  = var.gcp_region
}

# VPC network
resource "google_compute_network" "waf_vpc" {
  name                    = "waf-vpc-${var.environment}"
  auto_create_subnetworks = false
}

# Subnets
resource "google_compute_subnetwork" "waf_subnet" {
  name          = "waf-subnet-${var.environment}"
  network       = google_compute_network.waf_vpc.id
  ip_cidr_range = var.subnet_cidr
  region        = var.gcp_region

  private_ip_google_access = true
}

# Firewall rules
resource "google_compute_firewall" "allow_http" {
  name    = "allow-http-${var.environment}"
  network = google_compute_network.waf_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080", "9090"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["waf-instance"]
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal-${var.environment}"
  network = google_compute_network.waf_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.0.0.0/8"]
}

# Instance template
resource "google_compute_instance_template" "waf_template" {
  name        = "waf-template-${var.environment}"
  machine_type = var.machine_type

  tags = ["waf-instance", "http-server", "https-server"]

  disk {
    source_image = var.boot_image
    auto_delete  = true
    boot         = true
  }

  network_interface {
    network    = google_compute_network.waf_vpc.name
    subnetwork = google_compute_subnetwork.waf_subnet.name
    access_config {
      // External IP
    }
  }

  metadata = {
    startup-script = <<-EOF
      #!/bin/bash
      apt-get update
      apt-get install -y docker.io
      systemctl start docker
      systemctl enable docker
      docker run -d --restart unless-stopped \
        -p 8080:8080 -p 9090:9090 \
        -v /opt/waf/config:/app/config:ro \
        -v /opt/waf/rules:/app/rules:ro \
        ${var.waf_image}:latest
    EOF
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

# Managed Instance Group
resource "google_compute_instance_group_manager" "waf_mig" {
  name        = "waf-mig-${var.environment}"
  zone        = "${var.gcp_region}-a"
  target_size = var.desired_capacity

  named_port {
    name = "http"
    port = 8080
  }

  instance_template = google_compute_instance_template.waf_template.id

  auto_healing_links {
    health_check      = google_compute_health_check.waf_health.id
    initial_delay_sec = 300
  }
}

# Health check
resource "google_compute_health_check" "waf_health" {
  name               = "waf-health-${var.environment}"
  check_interval_sec = 30
  timeout_sec        = 5

  httphealth_check {
    port = 8080
    request_path = "/health"
  }
}

# AutoScaler
resource "google_compute_autoscaler" "waf_autoscaler" {
  name    = "waf-autoscaler-${var.environment}"
  zone    = "${var.gcp_region}-a"
  target  = google_compute_instance_group_manager.waf_mig.id

  autoscaling_policy {
    max_replicas    = var.max_replicas
    min_replicas    = var.min_replicas
    cooldown_period = 300

    cpu_utilization_target = 0.7
  }
}

# Load Balancer (Global HTTP(S) Load Balancer)
resource "google_compute_global_address" "waf_ip" {
  name = "waf-ip-${var.environment}"
}

resource "google_compute_target_pool" "waf_target_pool" {
  name                 = "waf-target-pool-${var.environment}"
  instance_group       = google_compute_instance_group_manager.waf_mig.instance_group
  health_checks        = [google_compute_health_check.waf_health.id]
}

resource "google_compute_global_forwarding_rule" "http" {
  name       = "waf-http-rule-${var.environment}"
  target     = google_compute_target_pool.waf_target_pool.id
  port_range = "80"

  ip_address = google_compute_global_address.waf_ip.id
}

resource "google_compute_global_forwarding_rule" "https" {
  name       = "waf-https-rule-${var.environment}"
  target     = google_compute_target_pool.waf_target_pool.id
  port_range = "443"

  ip_address = google_compute_global_address.waf_ip.id
}

# Cloud Armor (GCP's WAF)
resource "google_compute_security_policy" "waf_security_policy" {
  name        = "waf-security-policy-${var.environment}"
  description = "Cloud Armor security policy for WAF"

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
      rule_visibility = "STANDARD"
    }
  }

  rule {
    action      = "deny(403)"
    description = "Block SQL injection"
    condition {
      expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
    }
    priority = 1000
  }

  rule {
    action      = "deny(403)"
    description = "Block XSS"
    condition {
      expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
    }
    priority = 1001
  }

  rule {
    action      = "allow"
    description = "Allow all other traffic"
    priority    = 2147483647
  }
}

# Memorystore Redis for rate limiting
resource "google_redis_instance" "waf_redis" {
  name           = "waf-redis-${var.environment}"
  memory_size_gb = 1
  region         = var.gcp_region

  redis_version  = "REDIS_7_0"
  network        = google_compute_network.waf_vpc.id
  connect_mode   = "PRIVATE_SERVICE_ACCESS"

  tier = "BASIC"
}

# Cloud Logging sink
resource "google_logging_project_sink" "waf_sink" {
  name        = "waf-sink-${var.environment}"
  destination = "storage.googleapis.com/waf-logs-${var.environment}"

  filter = 'resource.type="gce_instance"'

  unique_writer_identity = true
}

# Variables
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "subnet_cidr" {
  description = "Subnet CIDR"
  type        = string
  default     = "10.0.0.0/24"
}

variable "machine_type" {
  description = "GCE machine type"
  type        = string
  default     = "e2-medium"
}

variable "boot_image" {
  description = "Boot image family"
  type        = string
  default     = "debian-12"
}

variable "waf_image" {
  description = "WAF Docker image"
  type        = string
  default     = "ghcr.io/username/waf:latest"
}

variable "desired_capacity" {
  description = "Desired MIG capacity"
  type        = number
  default     = 2
}

variable "min_replicas" {
  description = "Minimum replicas"
  type        = number
  default     = 1
}

variable "max_replicas" {
  description = "Maximum replicas"
  type        = number
  default     = 5
}

# Outputs
output "load_balancer_ip" {
  description = "Load balancer IP"
  value       = google_compute_global_address.waf_ip.address
}

output "redis_host" {
  description = "Redis host"
  value       = google_redis_instance.waf_redis.host
}

output "security_policy_name" {
  description = "Cloud Armor policy name"
  value       = google_compute_security_policy.waf_security_policy.name
}