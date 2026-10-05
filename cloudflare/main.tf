# Locals block to handle dynamic Cloudflare expression creation
locals {
  # If allowed_countries = ["MY", "SG"], 
  # countries will be ["ip.geoip.country ne \"MY\"", "ip.geoip.country ne \"SG\""]
  countries = [for c in var.allowed_countries : "ip.geoip.country ne \"${c}\""]
  # Eg, "ip.geoip.country ne \"MY\" and ip.geoip.country ne \"SG\""
  # https://developers.cloudflare.com/ruleset-engine/rules-language/
  geoblock_whitelist = "(${join(" and ", local.countries)})"
}

resource "cloudflare_ruleset" "geoblock" {
  kind    = "zone"
  name    = "default"
  phase   = "http_request_firewall_custom"
  zone_id = var.zone_id
  rules {
    action      = "skip"
    description = "Skip geoblock for tunnel hostname"
    enabled     = true
    expression  = "(http.host eq \"g.${var.zone}\") or (http.host eq \"f.${var.zone}\") or (http.host eq \"scrape.${var.zone}\")"
    action_parameters {
      ruleset = "current"
    }
    logging {
      enabled = true
    }
  }
  rules {
    action      = "block"
    description = "Blocking countries that are not in the whitelist."
    enabled     = true
    expression  = local.geoblock_whitelist 
  }
}

module "dns" {
  source  = "app.terraform.io/ahlooii/dns/cloudflare"
  version = "2.0.3"

  zone_id     = var.zone_id
  default_ttl = 300

  map_of_records = {
    "${var.primary}" = [{
        name    = "@"
        proxied = true
    }],
    "${var.zone}" = [
      {
        name    = "jellyfin"
        proxied = true
      },
      {
        name    = "auth"
        proxied = true
      },
      {
        name    = "librespeed"
        proxied = true
      },
      {
        name    = "syncthing"
        proxied = true
      },
      {
        name    = "nextcloud"
        proxied = true
      }
    ],

    "${var.email_route}" = [
      {
        name    = "mail"
        proxied = false
      },
      {
        name    = "webmail"
        proxied = false
      },
      {
        name     = var.zone
        proxied  = false
        priority = 10
        type     = "MX"
      }
    ],

    "${var.email_relay_route}" = [
      {
        name     = var.zone
        proxied  = false
        priority = 20
        type     = "MX"
      }
    ],
    "${var.spf_record}" = [
      {
        name    = var.zone
        proxied = false
        type    = "TXT"
      }
    ],
    "${var.dkim_record}" = [
      {
        name    = "x._domainkey"
        proxied = false
        type    = "TXT"
      }
    ]
  }
}


# Cloudflare Access — protect SSH tunnel with service token auth
resource "cloudflare_access_service_token" "tunnel_ssh" {
  account_id = var.account_id
  name       = "tunnel-ssh"
}

resource "cloudflare_access_application" "g" {
  zone_id                    = var.zone_id
  name                       = "g-ssh-tunnel"
  domain                     = "g.${var.zone}"
  type                       = "self_hosted"
  session_duration           = "720h"
  skip_interstitial          = true
  app_launcher_visible       = false
  auto_redirect_to_identity  = false
}

resource "cloudflare_access_policy" "g_service_auth" {
  application_id = cloudflare_access_application.g.id
  zone_id        = var.zone_id
  name           = "Service token auth"
  precedence     = 1
  decision       = "non_identity"

  include {
    service_token = [cloudflare_access_service_token.tunnel_ssh.id]
  }
}

output "access_client_id" {
  description = "CF-Access-Client-Id for SSH tunnel"
  value       = cloudflare_access_service_token.tunnel_ssh.client_id
  sensitive   = true
}

output "access_client_secret" {
  description = "CF-Access-Client-Secret for SSH tunnel"
  value       = cloudflare_access_service_token.tunnel_ssh.client_secret
  sensitive   = true
}

# Cloudflare Tunnel — oracle_account_one
# SSH:  cloudflared access ssh --hostname g.ahlooii.com
resource "random_id" "tunnel_secret_oracle_account_one" {
  byte_length = 32
}

resource "cloudflare_tunnel" "oracle_account_one" {
  account_id = var.account_id
  name       = "oracle-account-one"
  secret     = random_id.tunnel_secret_oracle_account_one.b64_std
  config_src = "cloudflare"
}

resource "cloudflare_tunnel_config" "oracle_account_one" {
  account_id = var.account_id
  tunnel_id  = cloudflare_tunnel.oracle_account_one.id

  config {
    ingress_rule {
      hostname = "g.${var.zone}"
      service  = "ssh://localhost:2279"
    }
    ingress_rule {
      hostname = "git.${var.zone}"
      service  = "http://localhost:3000"
    }
    ingress_rule {
      hostname = "f.${var.zone}"
      service  = "http://localhost:5000"
    }
    ingress_rule {
      hostname = "scrape.${var.zone}"
      service  = "http://127.0.0.1:8765"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

resource "cloudflare_record" "g" {
  zone_id = var.zone_id
  name    = "g"
  value   = "${cloudflare_tunnel.oracle_account_one.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_record" "oracle_a1" {
  zone_id = var.zone_id
  name    = "oracle-a1"
  value   = var.oracle_account_one
  type    = "A"
  proxied = true
}

resource "cloudflare_record" "wireguard" {
  zone_id = var.zone_id
  name    = "wireguard"
  value   = "oracle-a1.${var.zone}"
  type    = "CNAME"
  proxied = false
}

resource "cloudflare_record" "git" {
  zone_id = var.zone_id
  name    = "git"
  value   = "${cloudflare_tunnel.oracle_account_one.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_record" "f" {
  zone_id = var.zone_id
  name    = "f"
  value   = "${cloudflare_tunnel.oracle_account_one.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_record" "scrape" {
  zone_id = var.zone_id
  name    = "scrape"
  value   = "${cloudflare_tunnel.oracle_account_one.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_access_application" "f" {
  zone_id                   = var.zone_id
  name                      = "f-file-share"
  domain                    = "f.${var.zone}"
  type                      = "self_hosted"
  session_duration          = "720h"
  skip_interstitial         = true
  app_launcher_visible      = false
  auto_redirect_to_identity = false
}

resource "cloudflare_access_policy" "f_email_auth" {
  application_id = cloudflare_access_application.f.id
  zone_id        = var.zone_id
  name           = "Email OTP auth"
  precedence     = 1
  decision       = "allow"

  include {
    email = distinct(concat(var.cf_access_allowed_emails, var.cf_access_fileshare_emails))
  }
}

resource "cloudflare_access_application" "git" {
  zone_id                   = var.zone_id
  name                      = "git-access"
  domain                    = "git.${var.zone}"
  type                      = "self_hosted"
  session_duration          = "720h"
  skip_interstitial         = true
  app_launcher_visible      = false
  auto_redirect_to_identity = false
}

resource "cloudflare_access_policy" "git_email_auth" {
  application_id = cloudflare_access_application.git.id
  zone_id        = var.zone_id
  name           = "Email OTP auth"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.cf_access_allowed_emails
  }
}

output "tunnel_token_oracle_account_one" {
  description = "Token for cloudflared on Oracle account one"
  value       = base64encode(jsonencode({
    a = var.account_id
    t = cloudflare_tunnel.oracle_account_one.id
    s = random_id.tunnel_secret_oracle_account_one.b64_std
  }))
  sensitive = true
}

# resource "cloudflare_access_application" "kasm" {
#   app_launcher_visible       = true
#   auto_redirect_to_identity  = false
#   domain                     = "kasm.${var.zone}"
#   enable_binding_cookie      = false
#   http_only_cookie_attribute = true
#   name                       = "kasm"
#   self_hosted_domains        = ["kasm.${var.zone}"]
#   session_duration           = "24h"
#   skip_interstitial          = true
#   type                       = "self_hosted"
#   zone_id                    = var.zone_id
#   cors_headers {
#     allow_all_headers = true
#     allow_all_methods = true
#     allow_all_origins = true
#   }
# }