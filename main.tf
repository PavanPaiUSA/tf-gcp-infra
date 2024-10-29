resource "google_compute_network" "vpc_network" {
  project                         = var.project_id
  name                            = var.vpc_name
  delete_default_routes_on_create = true
  auto_create_subnetworks         = false
  routing_mode                    = var.routing_mode
}

resource "google_compute_subnetwork" "webapp_subnet" {
  name                     = var.webapp_subnet_name
  ip_cidr_range            = var.webapp_subnet_cidr
  network                  = google_compute_network.vpc_network.id
  region                   = var.region
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "db_subnet" {
  name          = var.db_subnet_name
  ip_cidr_range = var.db_subnet_cidr
  network       = google_compute_network.vpc_network.id
  region        = var.region
}

resource "google_compute_route" "webapp_route" {
  name             = var.webapp_route_name
  dest_range       = var.webapp_route_range
  network          = google_compute_network.vpc_network.id
  next_hop_gateway = var.next_hop_gateway
  priority         = 1000

}

resource "google_compute_firewall" "webapp_allow_firewall" {
  name    = var.webapp_allow_firewall_name
  network = google_compute_network.vpc_network.id
  allow {
    protocol = var.protocol
    ports    = [var.webapp_application_port]
  }
  target_tags   = [var.http_server_tag]
  source_ranges = [var.source_ranges]
}

resource "google_compute_firewall" "db_allow_firewall" {
  name    = var.db_allow_firewall_name
  network = google_compute_network.vpc_network.id
  allow {
    protocol = var.protocol
    ports    = [var.POSTGRES_DB_PORT, var.webapp_application_port]
  }
  target_tags   = [var.http_server_tag]
  source_ranges = [google_compute_subnetwork.webapp_subnet.ip_cidr_range]
}

resource "google_compute_firewall" "webapp_deny_firewall" {
  name    = var.webapp_deny_firewall_name
  network = google_compute_network.vpc_network.id
  deny {
    protocol = var.protocol
    ports    = [var.ssh_port]
  }
  source_ranges = [var.source_ranges]
}

resource "google_compute_global_address" "internal_ip_private_access" {
  project       = google_compute_network.vpc_network.project
  name          = var.vpc_private_service_access
  address_type  = var.private_access_address_type
  purpose       = var.purpose
  network       = google_compute_network.vpc_network.id
  prefix_length = var.prefix_length
}

resource "random_id" "db_name_suffix" {
  byte_length = 4
}

resource "google_sql_database_instance" "db_instance" {
  name                = "db-instance-${random_id.db_name_suffix.hex}"
  region              = var.region
  database_version    = var.database_version
  deletion_protection = var.db_deletion_protection

  depends_on = [google_service_networking_connection.private_vpc_connection]
  encryption_key_name = google_kms_crypto_key.cloudSql_key.id
  settings {
    availability_type = var.db_availability_type
    disk_type         = var.db_disk_type
    disk_size         = var.db_disk_size
    tier              = var.db_tier
    edition           = var.db_edition
    ip_configuration {
      ipv4_enabled    = var.ipv4_enabled
      private_network = google_compute_network.vpc_network.id
    }
  }
}

resource "google_sql_database" "db_webapp" {
  name     = var.db_name
  instance = google_sql_database_instance.db_instance.name
}

resource "random_password" "db_password" {
  length           = var.password_length
  special          = true
  override_special = var.override_special
}

resource "google_sql_user" "db_user" {
  name     = var.db_user
  instance = google_sql_database_instance.db_instance.name
  password = random_password.db_password.result
}


resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vpc_network.id
  service                 = var.service
  reserved_peering_ranges = [google_compute_global_address.internal_ip_private_access.name]
  deletion_policy         = var.deletion_policy
}

resource "google_service_account" "vm_service_account" {
  account_id   = var.vm_service_account_accountid
  display_name = var.vm_service_account_display_name
  project      = var.project_id
}

resource "google_project_iam_binding" "logging_admin" {
  project = var.project_id
  role    = var.logging_admin_role
  members = [
    "serviceAccount:${google_service_account.vm_service_account.email}",
  ]
}

resource "google_project_iam_binding" "monitoring_metric_writer" {
  project = var.project_id
  role    = var.monitoring_metric_writer_role
  members = [
    "serviceAccount:${google_service_account.vm_service_account.email}",
  ]
}

data "google_dns_managed_zone" "my_dns_zone" {
  name = var.google_dns_managed_zone_name
}

resource "google_dns_record_set" "my_dns_record" {
  name         = data.google_dns_managed_zone.my_dns_zone.dns_name
  type         = var.google_dns_record_set_type
  ttl          = var.google_dns_record_set_ttl
  managed_zone = data.google_dns_managed_zone.my_dns_zone.name
  rrdatas      = [google_compute_global_address.webapp_lb_ip.address]
}

resource "google_dns_record_set" "txt_record_spf" {
  name         = "mg.${data.google_dns_managed_zone.my_dns_zone.dns_name}"
  type         = "TXT"
  ttl          = 300
  managed_zone = data.google_dns_managed_zone.my_dns_zone.name

  rrdatas = [
    "v=spf1 include:mailgun.org ~all"
  ]

}

resource "google_dns_record_set" "txt_record_dkim" {
  name         = "k1._domainkey.mg.${data.google_dns_managed_zone.my_dns_zone.dns_name}"
  type         = "TXT"
  ttl          = 300
  managed_zone = data.google_dns_managed_zone.my_dns_zone.name

  rrdatas = [
    "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnWC8JU1T2+07hpq1Ou5+PvB8gPHviLscwId3QOzYkaoE/6wrxLLs9Na9AI3P+PrNEl1jUzgKyJHGwZqNsq049dhN7YhxeMKow6ORkYfSvDnglnPOd70BEEEsTkY8q3A3kVNbet4KC4ahuRkLFgBQvMa7SPqs3G1ojP6O3DsE5yQIDAQAB"
  ]

}

resource "google_dns_record_set" "mx_record" {
  name         = "mg.${data.google_dns_managed_zone.my_dns_zone.dns_name}"
  type         = "MX"
  ttl          = 300
  managed_zone = data.google_dns_managed_zone.my_dns_zone.name

  rrdatas = [
    "10 mxa.mailgun.org.", "20 mxb.mailgun.org."
  ]

}

resource "google_dns_record_set" "cname" {
  name         = "email.mg.${data.google_dns_managed_zone.my_dns_zone.dns_name}"
  managed_zone = data.google_dns_managed_zone.my_dns_zone.name
  type         = "CNAME"
  ttl          = 300
  rrdatas = [
    "mailgun.org."
  ]
}

resource "google_pubsub_topic" "verify_email" {
  name                       = "verify-email"
  message_retention_duration = "604800s"
}

resource "google_pubsub_subscription" "verify_email_pubsub_subscription" {
  name  = "verify-email-pubsub-subscription"
  topic = google_pubsub_topic.verify_email.name

  ack_deadline_seconds = 10
  push_config {
    push_endpoint = google_cloudfunctions2_function.verify_email_function.url
  }
}

data "google_iam_policy" "pubsub_viewer" {
  binding {
    role = "roles/pubsub.publisher"
    members = [
      "serviceAccount:${google_service_account.vm_service_account.email}",
    ]
  }
}

resource "google_pubsub_topic_iam_policy" "pubsub_policy" {
  project     = google_pubsub_topic.verify_email.project
  topic       = google_pubsub_topic.verify_email.name
  policy_data = data.google_iam_policy.pubsub_viewer.policy_data
}

data "google_iam_policy" "pubsub_editor" {
  binding {
    role = "roles/editor"
    members = [
      "serviceAccount:${google_service_account.vm_service_account.email}",
    ]
  }
}

resource "google_pubsub_subscription_iam_policy" "editor" {
  subscription = google_pubsub_subscription.verify_email_pubsub_subscription.name
  policy_data  = data.google_iam_policy.pubsub_editor.policy_data
}

resource "google_vpc_access_connector" "vpc_connector" {
  name          = "webapp-vpc-connector"
  network       = google_compute_network.vpc_network.self_link
  region        = var.region
  ip_cidr_range = "10.2.0.0/28"
}

resource "google_storage_bucket" "serverless-bucket" {
  name     = "serverless-pavan"
  location = "US"
}

resource "google_storage_bucket_object" "serverless-archive" {
  name   = "serverless.zip"
  bucket = google_storage_bucket.serverless-bucket.name
  source = "./serverless.zip"
}

resource "google_cloudfunctions2_function" "verify_email_function" {
  name        = "verify-email-function"
  description = "Verification of Email"
  location    = "us-east1"

  build_config {
    runtime     = "nodejs20"
    entry_point = "verifyEmail"
    source {
      storage_source {
        bucket = google_storage_bucket.serverless-bucket.name
        object = google_storage_bucket_object.serverless-archive.name
      }
    }
  }

  service_config {
    vpc_connector         = google_vpc_access_connector.vpc_connector.name
    max_instance_count    = 1
    available_memory      = "256M"
    service_account_email = google_service_account.vm_service_account.email
    environment_variables = {
      MAILGUN_API_KEY    = "6259c23f9c01cd6daaf0d36dd3694026-f68a26c9-2840ed22"
      MAILGUN_DOMAIN     = "mg.pavanpai.me"
      DNS                = "pavanpai.me"
      DB_HOST            = "${google_sql_database_instance.db_instance.ip_address.0.ip_address}"
      DB_DATABASE        = "${google_sql_database.db_webapp.name}"
      DB_USERNAME        = "${google_sql_user.db_user.name}"
      DB_PASSWORD        = "${google_sql_user.db_user.password}"
      MAILGUN_FROM_EMAIL = "postmaster@mg.pavanpai.me"
      DB_DIALECT         = "${var.POSTGRES_DB_DIALECT}"
      SERVER_PORT        = "${var.NODE_APP_PORT}"
      DB_DIALECT         = "${var.POSTGRES_DB_DIALECT}"
      NODE_APP_PORT      = "${var.NODE_APP_PORT}"

    }
  }

  event_trigger {
    trigger_region = "us-east1"
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.verify_email.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }
}


# resource "google_compute_instance" "vm_instance" {
#   name         = var.vm_name
#   zone         = var.vm_zone
#   machine_type = var.vm_machine_type

#   boot_disk {
#     initialize_params {
#       image = var.vm_image
#       type  = var.vm_disk_type
#       size  = var.vm_disk_size_gb
#     }
#   }

#   network_interface {
#     network    = google_compute_network.vpc_network.id
#     subnetwork = google_compute_subnetwork.webapp_subnet.id

#     access_config {
#       // Assigns a public IP address
#     }
#   }
#   tags = [var.http_server_tag]
#   depends_on = [
#     google_compute_subnetwork.webapp_subnet,
#     google_compute_firewall.webapp_allow_firewall,
#     google_compute_firewall.db_allow_firewall
#   ]
# metadata_startup_script = <<-EOT
#   #!/bin/bash
#   set -e

#   env_file="/opt/webapp/.env"

#   echo "SERVER_PORT=${var.NODE_APP_PORT}" > "$env_file"
#   echo "DB_USERNAME${google_sql_database.db_webapp.name}" >> "$env_file"
#   echo "DB_DIALECT=${var.POSTGRES_DB_DIALECT}" >> "$env_file"
#   echo "DB_HOST=${google_sql_database_instance.db_instance.ip_address.0.ip_address}" >> "$env_file"
#   echo "DB_PASSWORD=${google_sql_user.db_user.password}" >> "$env_file"
#   echo "DB_USERNAME=${google_sql_user.db_user.name}" >> "$env_file"
#   echo "APP_ENV=${var.APP_ENV}" >> "$env_file"
# EOT

# service_account {
#   email  = google_service_account.vm_service_account.email
#   scopes = [var.service_account_scope]
# }
# }
resource "google_project_iam_binding" "cloud_function_invoker" {
  project = var.project_id
  role    = var.cloud_function_invoker_role
  members = [
    "serviceAccount:${google_service_account.vm_service_account.email}",
  ]
}

resource "google_project_iam_binding" "cloud_run_invoker" {
  project = var.project_id
  role    = var.cloud_run_invoker_role

  members = [
    "serviceAccount:${google_service_account.vm_service_account.email}",
  ]
}

resource "google_compute_region_instance_template" "vm_instance_template" {
  name         = var.vm_name
  region       = var.region
  machine_type = var.vm_machine_type
  tags         = [var.http_server_tag]
  disk {
    source_image = var.vm_image
    disk_type    = var.vm_disk_type
    disk_size_gb = var.vm_disk_size_gb
    boot         = true
    auto_delete  = true
    disk_encryption_key {
      kms_key_self_link = google_kms_crypto_key.vm_machine_key.id
    }
  }
  depends_on = [google_kms_crypto_key_iam_binding.vm_encrypter_decrypter]
  network_interface {
    network    = google_compute_network.vpc_network.id
    subnetwork = google_compute_subnetwork.webapp_subnet.id

    access_config {
      network_tier = var.network_tier
    }
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    set -e
 
    env_file="/opt/webapp/.env"
 
    echo "SERVER_PORT=${var.NODE_APP_PORT}" > "$env_file"
    echo "DB_USERNAME${google_sql_database.db_webapp.name}" >> "$env_file"
    echo "DB_DIALECT=${var.POSTGRES_DB_DIALECT}" >> "$env_file"
    echo "DB_HOST=${google_sql_database_instance.db_instance.ip_address.0.ip_address}" >> "$env_file"
    echo "DB_PASSWORD=${google_sql_user.db_user.password}" >> "$env_file"
    echo "DB_USERNAME=${google_sql_user.db_user.name}" >> "$env_file"
    echo "APP_ENV=${var.APP_ENV}" >> "$env_file"
  EOT

  service_account {
    email  = google_service_account.vm_service_account.email
    scopes = [var.service_account_scope]
  }
}


resource "google_compute_health_check" "http_health_check" {
  name        = var.http_health_check_name
  description = var.http_health_check_description

  timeout_sec         = var.http_health_check_timeout_sec
  check_interval_sec  = var.http_health_check_check_interval_sec
  healthy_threshold   = var.http_health_check_healthy_threshold
  unhealthy_threshold = var.http_health_check_healthy_threshold

  http_health_check {
    port         = var.http_health_check_port
    request_path = var.http_health_check_request_path
  }
}


resource "google_compute_subnetwork" "lb_subnet" {
  name          = var.lb_subnet_name
  ip_cidr_range = var.lb_subnet_ip_cidr_range
  region        = var.region
  network       = google_compute_network.vpc_network.id
}


resource "google_compute_global_address" "webapp_lb_ip" {
  name = var.webapp_lb_ip_name
}

resource "google_compute_target_https_proxy" "webapp_https_proxy" {
  name             = var.webapp_https_proxy_name
  url_map          = google_compute_url_map.webapp_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.lb_ssl.id]
  # depends_on = [
  #   google_compute_managed_ssl_certificate.lb_ssl
  # ]
}

resource "google_compute_managed_ssl_certificate" "lb_ssl" {
  name = var.lb_ssl_name

  managed {
    domains = [var.lb_ssl_DNS]
  }
}
resource "google_project_iam_member" "instance_admin_role" {
  project = var.project_id
  role    = var.instance_admin_role_role
  member  = "serviceAccount:${google_service_account.vm_service_account.email}"
}

# resource "google_compute_ssl_certificate" "webapp_ssl" {
#   name        = "webapp-ssl-certificate"
#   private_key = file("path/to/private.key")
#   certificate = file("path/to/certificate.crt")
# }

resource "google_compute_url_map" "webapp_url_map" {
  name            = var.webapp_url_map_name
  description     = var.webapp_url_map_description
  default_service = google_compute_backend_service.webapp_backend_service.id
}

resource "google_compute_backend_service" "webapp_backend_service" {
  name                  = var.webapp_backend_service_name
  port_name             = var.webapp_backend_service_port_name
  protocol              = var.webapp_backend_service_protocol
  timeout_sec           = var.webapp_backend_service_timeout_sec
  enable_cdn            = var.webapp_backend_service_enable_cdn
  load_balancing_scheme = var.webapp_backend_service_load_balancing_scheme
  session_affinity      = var.webapp_backend_service_session_affinity

  backend {
    group           = google_compute_region_instance_group_manager.webapp_group_manager.instance_group
    balancing_mode  = var.webapp_backend_service_balancing_mode
    capacity_scaler = var.webapp_backend_service_capacity_scaler
  }

  health_checks = [google_compute_health_check.http_health_check.id]
}

resource "google_compute_global_forwarding_rule" "webapp" {
  name                  = var.google_compute_global_forwarding_rule_name
  ip_protocol           = var.google_compute_global_forwarding_rule_ip_protocol
  load_balancing_scheme = var.google_compute_global_forwarding_rule_load_balancing_scheme
  target                = google_compute_target_https_proxy.webapp_https_proxy.self_link
  port_range            = var.ssl_port_range
  ip_address            = google_compute_global_address.webapp_lb_ip.address
}

resource "google_compute_region_autoscaler" "webapp" {
  name   = var.autoscaler_name
  region = var.region
  target = google_compute_region_instance_group_manager.webapp_group_manager.self_link
  autoscaling_policy {
    max_replicas    = var.autoscaler_max_replicas
    min_replicas    = var.autoscaler_min_replicas
    cooldown_period = var.autoscaler_cooldown_period

    cpu_utilization {
      target = var.autoscaler_target
    }
  }

}


resource "google_compute_region_instance_group_manager" "webapp_group_manager" {
  name               = var.webapp_group_manager_name
  base_instance_name = var.webapp_group_manager_base_instance_name
  region             = var.region
  version {
    instance_template = google_compute_region_instance_template.vm_instance_template.self_link
  }

  named_port {
    name = var.named_port_name
    port = var.named_port_port
  }
  auto_healing_policies {
    health_check      = google_compute_health_check.http_health_check.id
    initial_delay_sec = 120
  }
  target_size = var.webapp_group_manager_target_size
}

resource "google_kms_key_ring" "webapp_keyring" {
  name     = "webapp-keyring-1"
  location = var.region
}

resource "google_kms_crypto_key" "vm_machine_key" {
  name            = "vm-machine-key-1"
  key_ring        = google_kms_key_ring.webapp_keyring.id
  rotation_period = "2592000s"

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_crypto_key" "cloudSql_key" {
  name            = "cloud-sql-key-1"
  key_ring        = google_kms_key_ring.webapp_keyring.id
  rotation_period = "2592000s"

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_crypto_key" "cloudStorage_key" {
  name            = "cloud-storage-key-1"
  key_ring        = google_kms_key_ring.webapp_keyring.id
  rotation_period = "2592000s"

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_crypto_key_iam_binding" "cloudSql_crypto_key" {
  crypto_key_id = google_kms_crypto_key.cloudSql_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = [
    "serviceAccount:${google_project_service_identity.gcp_sa_cloud_sql.email}",
  ]
}

resource "google_project_service_identity" "gcp_sa_cloud_sql" {
  provider = google-beta
  project  = var.project_id
  service  = "sqladmin.googleapis.com"
}

data "google_storage_project_service_account" "gcs_account" {
}


resource "google_kms_crypto_key_iam_binding" "encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.cloudStorage_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members = ["serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"
  ]
}




data "google_project" "project" {}

resource "google_kms_crypto_key_iam_binding" "vm_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.vm_machine_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = [
    "serviceAccount:service-${data.google_project.project.number}@compute-system.iam.gserviceaccount.com",
  ]
}