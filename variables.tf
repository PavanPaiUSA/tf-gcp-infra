variable "project_id" {
  type        = string
  description = "Project ID"
}

variable "region" {
  type        = string
  description = "Region for this infrastructure"
}

variable "vpc_name" {
  description = "Name for VPC"
}

variable "webapp_subnet_name" {
  description = "Subnet name for webapp"
}

variable "db_subnet_name" {
  description = "Subnet name for db"
}

variable "webapp_subnet_cidr" {
  description = "CIDR range for webapp"
}

variable "db_subnet_cidr" {
  description = "CIDR range for db"
}

variable "webapp_route_name" {
  description = "Router name for webapp subnet"
}

variable "webapp_route_range" {
  description = "Router range for webapp route"
}

variable "webapp_application_port" {
  description = "Application Port for the Webapp"
}

variable "vm_name" {
  description = "The name of the VM instance"
  type        = string
}

variable "vm_zone" {
  description = "The zone for the VM instance"
  type        = string
}

variable "vm_machine_type" {
  description = "The machine type for the VM instance"
  type        = string
}

variable "vm_image" {
  description = "The custom image for the VM boot disk"
  type        = string
}

variable "vm_disk_type" {
  description = "The disk type for the VM boot disk"
  type        = string
}
variable "routing_mode" {
  description = "The routing_mode"
  type        = string
}

variable "next_hop_gateway" {
  description = "The routing_mode"
  type        = string
}

variable "vm_disk_size_gb" {
  description = "The size of the VM boot disk in GB"
  type        = number
}

variable "global_port" {
  description = "The size of the VM boot disk in GB"
}

variable "database_version" {
  description = "Private access address type"
  type        = string
}

variable "db_deletion_protection" {
  description = "deletion protection for sql instance"
  type        = bool
}

variable "db_availability_type" {
  description = "database availability type"
  type        = string
}

variable "db_disk_type" {
  description = "database disk type"
  type        = string
}

variable "db_disk_size" {
  description = "database disk size"
  type        = number
}

variable "ipv4_enabled" {
  description = "ipv4 enabled value"
  type        = bool
}

variable "db_name" {
  description = "database name"
  type        = string

}

variable "db_edition" {
  description = "database edition value"
  type        = string
}

variable "db_tier" {
  description = "database tier value"
  type        = string
}

variable "db_user" {
  description = "database user"
  type        = string
}

variable "NODE_APP_PORT" {
  description = "Application Port"
  type        = string
}

variable "POSTGRES_DB_DIALECT" {
  description = "Postgres DB Dialect"
  type        = string
}

variable "POSTGRES_DB_PORT" {
  description = "Database Port"
  type        = number
}

variable "vpc_private_service_access" {
  description = "Name of the private service access"
  type        = string
}

variable "private_ip_address" {
  description = "Ip address for private service access"
  type        = string
}

variable "forwarding_rule_private_access" {
  description = "Forwarding rule for private service access"
  type        = string
}

variable "private_access_address_type" {
  description = "Private access address type"
  type        = string
}

variable "prefix_length" {
  description = "prefix length"
}

variable "purpose" {
  description = "Purpose for Private service connection"
  type        = string
}

variable "deletion_policy" {
  description = "Deletion policy"
  type        = string
}

variable "service" {
  description = "Service for google_service_networking_connection"
  type        = string
}

variable "password_length" {
  description = "Length of password for Db password"
  type        = number
}

variable "override_special" {
  description = "Special Characters in DB Random Password"
  type        = string
}

variable "http_server_tag" {
  description = "Server tag for http server"
  type        = string
}

variable "webapp_allow_firewall_name" {
  description = "Webapp allow Firewall"
  type        = string
}

variable "db_allow_firewall_name" {
  description = "DB allow Firewall"
  type        = string
}

variable "webapp_deny_firewall_name" {
  description = "Webapp Deny Firewall"
  type        = string
}

variable "ssh_port" {
  description = "Ssh Port"
  type        = string
}

variable "protocol" {
  description = "Protocols"
  type        = string
}
variable "source_ranges" {
  description = "Source Ranges"
  type        = string
}

variable "service_account_scope" {
  description = "Service Account scopes"
  type        = string
}

variable "google_dns_record_set_type" {
  description = "Google DNS record set Type"
  type        = string
}

variable "google_dns_record_set_ttl" {
  description = "Google DNS record set TTL"
  type        = number
}

variable "google_dns_managed_zone_name" {
  description = "Google DNS Managed Zone Name"
  type        = string
}

variable "logging_admin_role" {
  description = "Logging Admin Role"
  type        = string
}

variable "monitoring_metric_writer_role" {
  description = "Monitoring Metric Role"
  type        = string
}

variable "vm_service_account_accountid" {
  description = "Service Account id"
  type        = string
}

variable "vm_service_account_display_name" {
  description = "Service Account Display Name"
  type        = string
}

variable "APP_ENV" {
  description = "app variable environment"
  type        = string
}

# variable "txt_record_spf_rrdatas" {
#   description = "app variable environment"
#   type        = string
# }

# variable "txt_record_dkim_rrdatas" {
#   description = "app variable environment"
#   type        = string
# }

# variable "mx_record_rrdatas" {
#   description = "app variable environment"
#   type        = string
# }

# variable "cname_rrdatas" {
#   description = "app variable environment"
#   type        = string
# }

# variable "google_pubsub_topic_verify_email_name" {
#   description = "app variable environment"
#   type        = string
# }

# variable "google_pubsub_topic_verify_email_message_retention_duration" {
#   description = "app variable environment"
#   type        = string
# }

variable "cloud_run_invoker_role" {
  description = "The IAM role for invoking Cloud Run services"
  type        = string
  default     = "roles/cloudfunctions.invoker"
}

variable "http_health_check_name" {
  description = "Name of the HTTP health check"
  type        = string
  default     = "http-health-check"
}

variable "http_health_check_description" {
  description = "Description of the HTTP health check"
  type        = string
  default     = "Health check via http"
}

variable "http_health_check_timeout_sec" {
  description = "Timeout in seconds for the HTTP health check"
  type        = number
  default     = 10
}

variable "http_health_check_check_interval_sec" {
  description = "Interval in seconds between each health check"
  type        = number
  default     = 10
}

variable "http_health_check_healthy_threshold" {
  description = "Number of successful health checks required to consider the service healthy"
  type        = number
  default     = 3
}

variable "http_health_check_unhealthy_threshold" {
  description = "Number of failed health checks required to consider the service unhealthy"
  type        = number
  default     = 3
}

variable "http_health_check_port" {
  description = "Port to use for the HTTP health check"
  type        = string
  default     = "3000"
}

variable "http_health_check_request_path" {
  description = "Request path for the HTTP health check"
  type        = string
  default     = "/healthz"
}

variable "lb_subnet_name" {
  description = "Name of the Load Balancer subnet"
  type        = string
  default     = "lb-subnet"
}

variable "lb_subnet_ip_cidr_range" {
  description = "IP CIDR range for the Load Balancer subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "webapp_lb_ip_name" {
  description = "Name for the IP address of the web application load balancer"
  type        = string
  default     = "web-app-lb-ip"
}

variable "webapp_https_proxy_name" {
  description = "Name of the HTTPS proxy for the web application"
  type        = string
  default     = "test-proxy"
}

variable "lb_ssl_name" {
  description = "Name of the SSL certificate for the Load Balancer"
  type        = string
  default     = "webapp-service-ssl-cert"
}

variable "lb_ssl_DNS" {
  description = "DNS name for the SSL certificate of the Load Balancer"
  type        = string
  default     = "cloudcsye6225rahul.me"
}

variable "instance_admin_role_role" {
  description = "IAM role for instance administration"
  type        = string
  default     = "roles/compute.instanceAdmin"
}

variable "webapp_url_map_name" {
  description = "Name for the web application URL map"
  type        = string
  default     = "webapp-url-map"
}

variable "webapp_url_map_description" {
  description = "Description of the web application URL map"
  type        = string
  default     = "webapp url map"
}

variable "webapp_backend_service_name" {
  description = "Name for the backend service of the web application"
  type        = string
  default     = "backend-service"
}

variable "webapp_backend_service_port_name" {
  description = "Port name for the web application backend service"
  type        = string
  default     = "http"
}

variable "webapp_backend_service_protocol" {
  description = "Protocol used by the web application backend service"
  type        = string
  default     = "HTTP"
}

variable "webapp_backend_service_timeout_sec" {
  description = "Timeout in seconds for the web application backend service"
  type        = number
  default     = 30
}

variable "webapp_backend_service_enable_cdn" {
  description = "Boolean to enable or disable CDN for the web application backend service"
  type        = bool
  default     = true
}

variable "webapp_backend_service_load_balancing_scheme" {
  description = "Load balancing scheme for the web application backend service"
  type        = string
  default     = "EXTERNAL_MANAGED"
}

variable "webapp_backend_service_session_affinity" {
  description = "Session affinity type for the web application backend service"
  type        = string
  default     = "CLIENT_IP"
}

variable "webapp_backend_service_balancing_mode" {
  description = "Balancing mode for the web application backend service"
  type        = string
  default     = "UTILIZATION"
}

variable "webapp_backend_service_capacity_scaler" {
  description = "Capacity scaler for the web application backend service"
  type        = number
  default     = 1.0
}

variable "google_compute_global_forwarding_rule_name" {
  description = "Name for the global forwarding rule of the web application"
  type        = string
  default     = "web-app-load-balancer"
}

variable "google_compute_global_forwarding_rule_ip_protocol" {
  description = "IP protocol for the global forwarding rule"
  type        = string
  default     = "TCP"
}

variable "google_compute_global_forwarding_rule_load_balancing_scheme" {
  description = "Load balancing scheme for the global forwarding rule"
  type        = string
  default     = "EXTERNAL_MANAGED"
}

variable "ssl_port_range" {
  description = "Port range for SSL traffic"
  type        = string
  default     = "443"
}

variable "autoscaler_name" {
  description = "Name for the autoscaler"
  type        = string
  default     = "webapp-autoscaler"
}

variable "autoscaler_max_replicas" {
  description = "Maximum number of replicas for autoscaling"
  type        = number
  default     = 6
}

variable "autoscaler_min_replicas" {
  description = "Minimum number of replicas for autoscaling"
  type        = number
  default     = 3
}

variable "autoscaler_cooldown_period" {
  description = "Cooldown period for autoscaling, in seconds"
  type        = number
  default     = 30
}

variable "autoscaler_target" {
  description = "Target CPU utilization for autoscaling"
  type        = number
  default     = 0.2
}

variable "webapp_group_manager_name" {
  description = "Name for the web application instance group manager"
  type        = string
  default     = "webapp-group-manager"
}

variable "webapp_group_manager_base_instance_name" {
  description = "Base instance name for the web application instance group manager"
  type        = string
  default     = "webapp"
}

variable "named_port_name" {
  description = "Name for the named port in the instance group"
  type        = string
  default     = "http"
}

variable "named_port_port" {
  description = "Port number for the named port in the instance group"
  type        = number
  default     = 3000
}

variable "auto_healing_policies_initial_delay_sec" {
  description = "Initial delay in seconds for the auto-healing policy"
  type        = number
  default     = 120
}

variable "webapp_group_manager_target_size" {
  description = "Target size for the web application instance group manager"
  type        = number
  default     = 3
}

variable "cloud_function_service_account_account_id" {
  description = "The account ID for the Cloud Function service account"
  type        = string
  default     = "cloud-function-sa"
}

variable "cloud_function_service_account_display_name" {
  description = "The display name for the Cloud Function service account"
  type        = string
  default     = "Cloud Function Service Account"
}

variable "network_tier" {
  description = "Network Tier"
  type        = string
  default     = "PREMIUM"
}

variable "cloud_function_invoker_role" {
  description = "The IAM role for invoking Cloud Functions"
  type        = string
  default     = "roles/run.invoker"
}