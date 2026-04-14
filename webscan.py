#!/usr/bin/env python3
"""
WebScan v2 - Advanced Website Security Scanner

New in v2:
  - Proxy support (HTTP, HTTPS, SOCKS4, SOCKS5)
  - Concurrent sensitive-file probing (--threads)
  - JavaScript file analysis for secrets and source maps
  - WAF detection
  - Technology / CMS fingerprinting
  - TLS 1.0 / 1.1 detection
  - Subresource Integrity (SRI) checks
  - CORS advanced checks (reflected origin, null origin)
  - Host header injection test
  - CRLF injection test
  - GraphQL introspection test
  - WordPress-specific checks (user enum, xmlrpc, wp-cron)
  - Error page information disclosure
  - Reflected parameter detection (basic XSS)
  - SSRF-prone parameter names
  - Email address harvesting
  - HTML report generation (--output-html)
  - Rate limiting (--rate-limit)
  - Automatic retry with backoff
  - Supabase: secret/publishable key patterns, JWT role checks, REST/storage probes
  - Dev/Ops: health/version/debug routes, .well-known probes, redirect chain, TTFB/slow responses
  - Frontend smoke: HTML/lang/viewport/canonical/h1/title, optional internal link HEAD check (--no-link-check)

Usage:
    python webscan.py https://example.com
    python webscan.py https://example.com --crawl --depth 2
    python webscan.py https://example.com --proxy socks5://127.0.0.1:1080
    python webscan.py https://example.com --proxy http://user:pass@proxy:8080
    python webscan.py https://example.com --threads 20 --rate-limit 0.2
    python webscan.py https://example.com --output report.json --output-html report.html
    python webscan.py https://example.com --min-severity HIGH --no-ssl-verify
"""

# ── Standard library ──────────────────────────────────────────────────────────
import re
import ssl
import json
import socket
import argparse
import datetime
import threading
import time
import urllib.parse
import concurrent.futures
import html as html_module
import warnings
import hashlib
import base64
from dataclasses import dataclass
from typing import List, Optional, Set, Dict, Tuple
from collections import defaultdict

# ── Third-party ───────────────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from bs4 import BeautifulSoup, Comment
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("    Run: pip install -r requirements.txt")
    raise SystemExit(1)


# ═════════════════════════════════════════════════════════════════════════════
# SEVERITY
# ═════════════════════════════════════════════════════════════════════════════

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER: Dict[str, int] = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

SEVERITY_COLOR: Dict[str, str] = {
    CRITICAL: Fore.RED + Style.BRIGHT,
    HIGH:     Fore.RED,
    MEDIUM:   Fore.YELLOW,
    LOW:      Fore.CYAN,
    INFO:     Fore.WHITE,
}

SEVERITY_HTML: Dict[str, str] = {
    CRITICAL: "#dc2626",
    HIGH:     "#ea580c",
    MEDIUM:   "#d97706",
    LOW:      "#2563eb",
    INFO:     "#6b7280",
}


# ═════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    url: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ═════════════════════════════════════════════════════════════════════════════
# SECRET PATTERNS
# ═════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # AWS
    ("AWS Access Key ID",
     r"AKIA[0-9A-Z]{16}", CRITICAL),
    ("AWS Secret Access Key",
     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", CRITICAL),
    ("AWS Session Token",
     r"FwoGZXIvYXdzE[0-9A-Za-z+/=]{100,}", CRITICAL),
    # Google
    ("Google API Key",
     r"AIza[0-9A-Za-z\-_]{35}", HIGH),
    ("Google OAuth Token",
     r"ya29\.[0-9A-Za-z\-_]+", HIGH),
    ("GCP Service Account JSON",
     r'"type"\s*:\s*"service_account"', CRITICAL),
    # GitHub
    ("GitHub Personal Token",
     r"ghp_[0-9a-zA-Z]{36}", CRITICAL),
    ("GitHub OAuth Token",
     r"gho_[0-9a-zA-Z]{36}", CRITICAL),
    ("GitHub App Token",
     r"(ghu|ghs|ghr)_[0-9a-zA-Z]{36}", CRITICAL),
    ("GitHub Fine-grained Token",
     r"github_pat_[0-9a-zA-Z_]{82}", CRITICAL),
    # GitLab
    ("GitLab Personal Token",
     r"glpat-[0-9a-zA-Z\-_]{20}", CRITICAL),
    # Stripe
    ("Stripe Live Secret Key",
     r"sk_live_[0-9a-zA-Z]{24,}", CRITICAL),
    ("Stripe Live Publishable Key",
     r"pk_live_[0-9a-zA-Z]{24,}", HIGH),
    ("Stripe Test Secret Key",
     r"sk_test_[0-9a-zA-Z]{24,}", MEDIUM),
    # Slack
    ("Slack Bot Token",
     r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}", CRITICAL),
    ("Slack User Token",
     r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[0-9a-f]{32}", CRITICAL),
    ("Slack Webhook",
     r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+", HIGH),
    ("Slack App Token",
     r"xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+", CRITICAL),
    # Twilio
    ("Twilio Account SID",
     r"AC[0-9a-f]{32}", HIGH),
    ("Twilio Auth Token",
     r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]", CRITICAL),
    # Email / SMS providers
    ("SendGrid API Key",
     r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", CRITICAL),
    ("Mailgun API Key",
     r"key-[0-9a-zA-Z]{32}", HIGH),
    ("Mailchimp API Key",
     r"[0-9a-f]{32}-us[0-9]{1,2}", HIGH),
    ("Postmark Server Token",
     r"(?i)postmark.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", HIGH),
    # Firebase
    ("Firebase FCM Server Key",
     r"AAAA[0-9A-Za-z_-]{7}:[0-9A-Za-z_-]{140}", CRITICAL),
    # Payments
    ("Stripe Live Secret Key (alt)",
     r"rk_live_[0-9a-zA-Z]{24,}", CRITICAL),
    ("Square Access Token",
     r"sq0atp-[0-9A-Za-z\-_]{22}", CRITICAL),
    ("Square OAuth Secret",
     r"sq0csp-[0-9A-Za-z\-_]{43}", CRITICAL),
    ("PayPal Braintree Token",
     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", CRITICAL),
    ("Shopify Access Token",
     r"shpat_[0-9a-fA-F]{32}", CRITICAL),
    ("Shopify Shared Secret",
     r"shpss_[0-9a-fA-F]{32}", CRITICAL),
    # Cloud / Infra
    ("Heroku API Key",
     r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", CRITICAL),
    ("Azure Storage Connection String",
     r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};", CRITICAL),
    ("Azure Function Key",
     r"(?i)(code|key)=[A-Za-z0-9_\-/+=]{30,}", MEDIUM),
    ("Cloudinary URL",
     r"cloudinary://[0-9]+:[0-9A-Za-z_\-]+@[a-z]+", HIGH),
    ("Okta API Token",
     r"00[0-9A-Za-z_-]{40}", HIGH),
    ("HashiCorp Vault Token",
     r"hvs\.[A-Za-z0-9_\-]{24,}", HIGH),
    # Dev / Infra tokens
    ("NPM Auth Token",
     r"npm_[A-Za-z0-9]{36}", HIGH),
    ("PyPI Upload Token",
     r"pypi-[A-Za-z0-9_-]{40,}", HIGH),
    ("Docker Hub Token",
     r"(?i)docker.{0,20}['\"][0-9a-zA-Z_\-]{36,}['\"]", MEDIUM),
    # Social / messaging
    ("Telegram Bot Token",
     r"[0-9]{8,10}:[0-9A-Za-z_-]{35}", HIGH),
    ("Discord Bot Token",
     r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", CRITICAL),
    ("Mapbox Token",
     r"pk\.eyJ1IjoiW[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", HIGH),
    # Keys / Certs
    ("RSA Private Key",
     r"-----BEGIN RSA PRIVATE KEY-----", CRITICAL),
    ("DSA Private Key",
     r"-----BEGIN DSA PRIVATE KEY-----", CRITICAL),
    ("EC Private Key",
     r"-----BEGIN EC PRIVATE KEY-----", CRITICAL),
    ("PKCS8 Private Key",
     r"-----BEGIN PRIVATE KEY-----", CRITICAL),
    ("OpenSSH Private Key",
     r"-----BEGIN OPENSSH PRIVATE KEY-----", CRITICAL),
    ("PGP Private Key",
     r"-----BEGIN PGP PRIVATE KEY BLOCK-----", CRITICAL),
    # Auth / tokens
    ("JWT Token",
     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", HIGH),
    ("Bearer Token",
     r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_=+/]{20,}', HIGH),
    ("Basic Auth in URL",
     r"https?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-]{3,}@[A-Za-z0-9.\-]{4,}", HIGH),
    # Database
    ("Database Connection String",
     r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|sqlserver|oracle)://[^\s\"'<>]{8,}", HIGH),
    # Generic
    ("Generic Secret/Password Assignment",
     r"(?i)(secret|password|passwd|api_key|apikey|access_token|auth_token|client_secret|private_key)\s*[:=]\s*['\"][^\s'\"]{8,}['\"]", MEDIUM),
    ("Generic API Key in Header",
     r'(?i)["\']?(x-api-key|api-key|apikey)["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', MEDIUM),
    ("Private IP Address",
     r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}", LOW),
    # HubSpot / Salesforce / Atlassian
    ("HubSpot API Key",
     r"(?i)hubspot.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", HIGH),
    ("Atlassian API Token",
     r"(?i)atlassian.{0,20}['\"][A-Za-z0-9_\-]{24,}['\"]", HIGH),
    ("Sentry DSN",
     r"https://[0-9a-f]{20,}@[a-z0-9_.-]+\.ingest\.(?:us\.)?sentry\.io/\d+",
     MEDIUM),
    # Supabase (https://supabase.com/docs/guides/api/api-keys)
    ("Supabase Secret Key (sb_secret_)",
     r"sb_secret_[A-Za-z0-9_\-]{20,}", CRITICAL),
    ("Supabase Publishable Key (sb_publishable_)",
     r"sb_publishable_[A-Za-z0-9_\-]{20,}", LOW),
    ("Supabase URL in env-style assignment",
     r"(?i)(SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|VITE_SUPABASE_URL|EXPO_PUBLIC_SUPABASE_URL|NUXT_PUBLIC_SUPABASE_URL|PUBLIC_SUPABASE_URL)\s*[=:]\s*['\"]https?://[a-z0-9_-]+\.supabase\.co/?['\"]",
     MEDIUM),
    ("Supabase Service Role env assignment",
     r"(?i)SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*['\"][^'\"]{20,}['\"]", CRITICAL),
]


# ═════════════════════════════════════════════════════════════════════════════
# SENSITIVE FILES
# ═════════════════════════════════════════════════════════════════════════════

SENSITIVE_FILES: List[Tuple[str, str, str]] = [
    # Environment files
    ("/.env",                       "Environment variables",              CRITICAL),
    ("/.env.local",                 "Local environment file",             CRITICAL),
    ("/.env.production",            "Production environment file",        CRITICAL),
    ("/.env.staging",               "Staging environment file",           CRITICAL),
    ("/.env.backup",                "Backup environment file",            CRITICAL),
    ("/.env.example",               "Example env (may have real values)", MEDIUM),
    ("/.env.development",           "Development environment file",       HIGH),
    # Git
    ("/.git/config",                "Git config (remote URLs/creds)",     HIGH),
    ("/.git/HEAD",                  "Git HEAD ref",                       HIGH),
    ("/.git/COMMIT_EDITMSG",        "Last git commit message",            MEDIUM),
    ("/.git/logs/HEAD",             "Git commit log",                     MEDIUM),
    ("/.git/refs/heads/master",     "Git master branch ref",              MEDIUM),
    ("/.git/refs/heads/main",       "Git main branch ref",                MEDIUM),
    ("/.gitignore",                 "Reveals directory structure",        LOW),
    # SVN
    ("/.svn/entries",               "SVN metadata",                       HIGH),
    ("/.svn/wc.db",                 "SVN working copy database",          HIGH),
    # CMS / Framework
    ("/wp-config.php",              "WordPress credentials",              CRITICAL),
    ("/wp-config.php.bak",          "WordPress config backup",            CRITICAL),
    ("/wp-config.php~",             "WordPress config editor backup",     CRITICAL),
    ("/wp-config-sample.php",       "WP sample config",                   LOW),
    ("/configuration.php",          "Joomla configuration",               HIGH),
    ("/config.php",                 "PHP configuration",                  HIGH),
    ("/config.php.bak",             "PHP config backup",                  HIGH),
    ("/config/database.yml",        "Rails database config",              CRITICAL),
    ("/database.yml",               "Database config",                    CRITICAL),
    ("/config/secrets.yml",         "Rails secrets",                      CRITICAL),
    ("/settings.py",                "Django settings",                    HIGH),
    ("/local_settings.py",          "Django local settings",              HIGH),
    # Web server
    ("/.htpasswd",                  "Apache password file",               CRITICAL),
    ("/.htaccess",                  "Apache access control",              MEDIUM),
    ("/web.config",                 "IIS/ASP.NET configuration",          HIGH),
    ("/server.xml",                 "Tomcat server config",               HIGH),
    # Spring Boot Actuator (very commonly exposed)
    ("/actuator",                   "Spring Boot Actuator index",         HIGH),
    ("/actuator/env",               "Spring Boot env (all properties)",   CRITICAL),
    ("/actuator/beans",             "Spring Boot bean definitions",       MEDIUM),
    ("/actuator/mappings",          "Spring Boot URL mappings",           MEDIUM),
    ("/actuator/heapdump",          "Spring Boot heap dump (CRITICAL)",   CRITICAL),
    ("/actuator/threaddump",        "Spring Boot thread dump",            MEDIUM),
    ("/actuator/info",              "Spring Boot app info",               INFO),
    ("/actuator/health",            "Spring Boot health",                 INFO),
    ("/actuator/logfile",           "Spring Boot log file",               HIGH),
    ("/actuator/httptrace",         "Spring Boot HTTP trace",             HIGH),
    # Diagnostic
    ("/phpinfo.php",                "PHP full configuration",             HIGH),
    ("/info.php",                   "PHP info page",                      HIGH),
    ("/test.php",                   "PHP test file",                      MEDIUM),
    ("/server-status",              "Apache server-status",               HIGH),
    ("/server-info",                "Apache server-info",                 HIGH),
    ("/elmah.axd",                  "ASP.NET ELMAH error log",            HIGH),
    ("/trace.axd",                  "ASP.NET trace info",                 HIGH),
    ("/console",                    "Web console (may allow RCE)",        CRITICAL),
    # OS artifacts
    ("/.DS_Store",                  "macOS metadata (reveals filenames)", LOW),
    ("/Thumbs.db",                  "Windows thumbnail cache",            LOW),
    # Database dumps / backups
    ("/backup.zip",                 "Site backup archive",                CRITICAL),
    ("/backup.tar.gz",              "Site backup archive",                CRITICAL),
    ("/backup.sql",                 "Database backup",                    CRITICAL),
    ("/db.sql",                     "Database dump",                      CRITICAL),
    ("/dump.sql",                   "Database dump",                      CRITICAL),
    ("/database.sql",               "Database dump",                      CRITICAL),
    ("/site.sql",                   "Database dump",                      CRITICAL),
    ("/data.sql",                   "Database dump",                      CRITICAL),
    # SSH / Shell
    ("/.bash_history",              "Shell command history",              CRITICAL),
    ("/.bash_profile",              "Bash profile",                       HIGH),
    ("/.ssh/id_rsa",                "SSH RSA private key",                CRITICAL),
    ("/.ssh/id_dsa",                "SSH DSA private key",                CRITICAL),
    ("/.ssh/id_ecdsa",              "SSH ECDSA private key",              CRITICAL),
    ("/.ssh/id_ed25519",            "SSH Ed25519 private key",            CRITICAL),
    ("/.ssh/authorized_keys",       "SSH authorized keys",                HIGH),
    ("/id_rsa",                     "SSH private key in web root",        CRITICAL),
    # Secrets files
    ("/secrets.json",               "Secrets JSON file",                  CRITICAL),
    ("/credentials.json",           "Google OAuth credentials",           CRITICAL),
    ("/service-account.json",       "GCP service account key",            CRITICAL),
    ("/key.pem",                    "PEM private key",                    CRITICAL),
    ("/server.key",                 "Server private key",                 CRITICAL),
    ("/private.key",                "Private key",                        CRITICAL),
    ("/.npmrc",                     "NPM config (may have tokens)",       HIGH),
    ("/.pypirc",                    "PyPI credentials",                   HIGH),
    ("/.netrc",                     "Network credentials (FTP/HTTP)",     CRITICAL),
    # Docker / CI / CD
    ("/Dockerfile",                 "Docker build config",                MEDIUM),
    ("/docker-compose.yml",         "Docker Compose config",              MEDIUM),
    ("/docker-compose.yaml",        "Docker Compose config",              MEDIUM),
    ("/.travis.yml",                "Travis CI config",                   MEDIUM),
    ("/.circleci/config.yml",       "CircleCI config",                    MEDIUM),
    ("/Jenkinsfile",                "Jenkins pipeline",                   MEDIUM),
    # Package manifests
    ("/package.json",               "Node.js manifest",                   LOW),
    ("/composer.json",              "PHP Composer manifest",              LOW),
    ("/requirements.txt",           "Python dependencies",                LOW),
    ("/Gemfile",                    "Ruby Gemfile",                       LOW),
    # API / Docs
    ("/swagger.json",               "Swagger/OpenAPI spec",               MEDIUM),
    ("/swagger.yaml",               "Swagger/OpenAPI spec",               MEDIUM),
    ("/openapi.json",               "OpenAPI spec",                       MEDIUM),
    ("/api-docs",                   "API documentation",                  MEDIUM),
    ("/graphql",                    "GraphQL endpoint",                   INFO),
    ("/api/graphql",                "GraphQL API",                        INFO),
    # Admin / DB management
    ("/admin",                      "Admin panel",                        MEDIUM),
    ("/admin.php",                  "Admin PHP panel",                    MEDIUM),
    ("/phpmyadmin/",                "phpMyAdmin",                         HIGH),
    ("/pma/",                       "phpMyAdmin (alias)",                 HIGH),
    ("/adminer.php",                "Adminer DB manager",                 HIGH),
    # Cross-domain
    ("/crossdomain.xml",            "Flash cross-domain policy",          MEDIUM),
    ("/clientaccesspolicy.xml",     "Silverlight cross-domain policy",    MEDIUM),
    # Standard
    ("/robots.txt",                 "Robots exclusion file",              INFO),
    ("/sitemap.xml",                "XML sitemap",                        INFO),
    ("/security.txt",               "Security contact info",              INFO),
    ("/.well-known/security.txt",   "Security contact info",              INFO),
    # WordPress extras
    ("/xmlrpc.php",                 "WordPress XML-RPC (attack surface)", MEDIUM),
    ("/wp-cron.php",                "WordPress WP-Cron",                  LOW),
    ("/wp-json/wp/v2/users",        "WordPress user enumeration",         HIGH),
    # Metrics
    ("/metrics",                    "Prometheus metrics",                 MEDIUM),
    ("/_cat/indices",               "Elasticsearch index list",           HIGH),
    ("/_cluster/health",            "Elasticsearch cluster health",       MEDIUM),
    # Supabase (local / leaked project config)
    ("/supabase/config.toml",       "Supabase local project config",      HIGH),
    ("/.supabase/config.toml",      "Supabase CLI linked project config", HIGH),
    ("/supabase/.env",              "Supabase env (may contain secrets)", CRITICAL),
    ("/supabase/seed.sql",          "Supabase seed SQL (may leak data)",  MEDIUM),
]

# Health, version, debug, API docs, and .well-known (internal QA / staging recon)
DEV_AND_OBSERVABILITY_PATHS: List[Tuple[str, str, str]] = [
    ("/health",                     "Health check",                       INFO),
    ("/health/",                    "Health check",                       INFO),
    ("/healthz",                    "Kubernetes-style liveness",          INFO),
    ("/ready",                      "Readiness probe",                    INFO),
    ("/readyz",                     "Kubernetes readiness",               INFO),
    ("/readiness",                  "Readiness endpoint",                 INFO),
    ("/live",                       "Liveness alias",                     INFO),
    ("/livez",                      "Kubernetes live",                    INFO),
    ("/alive",                      "Alive probe",                        INFO),
    ("/status",                     "Status page",                        INFO),
    ("/status.json",                "JSON status",                        LOW),
    ("/version",                    "Version string",                     LOW),
    ("/api/health",                 "API health",                         INFO),
    ("/api/healthz",                "API healthz",                        INFO),
    ("/api/status",                 "API status",                         INFO),
    ("/api/version",                "API version",                        LOW),
    ("/api/v1/health",              "API v1 health",                      INFO),
    ("/api/v2/health",              "API v2 health",                      INFO),
    ("/v1/health",                  "Versioned health",                   INFO),
    ("/ping",                       "Ping endpoint",                      INFO),
    ("/heartbeat",                  "Heartbeat",                          INFO),
    ("/debug",                      "Debug route",                        MEDIUM),
    ("/debug/",                     "Debug area",                         MEDIUM),
    ("/debug/vars",                 "Expvar / runtime vars (Go)",         HIGH),
    ("/internal/debug",             "Internal debug",                     HIGH),
    ("/_debug",                     "Framework debug",                    MEDIUM),
    ("/_profiler",                  "Profiler UI (Symfony/legacy)",       HIGH),
    ("/telescope",                  "Laravel Telescope",                  HIGH),
    ("/horizon",                    "Laravel Horizon dashboard",          MEDIUM),
    ("/_debugbar/open",             "Debug bar open handler",             MEDIUM),
    ("/rails/info",                 "Rails info (routes/properties)",     HIGH),
    ("/rails/mailers",              "Rails mailer previews",              MEDIUM),
    ("/redoc",                      "ReDoc API UI",                       INFO),
    ("/scalar",                     "Scalar API UI",                      INFO),
    ("/rapidoc",                    "RapiDoc API UI",                     INFO),
    ("/api-docs/",                  "Swagger UI path",                    INFO),
    ("/swagger-ui.html",            "Spring Swagger UI",                  INFO),
    ("/v2/api-docs",                "Springfox OpenAPI JSON",             MEDIUM),
    ("/v3/api-docs",                "Springdoc OpenAPI",                  MEDIUM),
    ("/api/swagger.json",           "Swagger JSON",                       MEDIUM),
    ("/.well-known/apple-app-site-association", "iOS universal links",    INFO),
    ("/.well-known/assetlinks.json", "Android App Links",                 INFO),
    ("/.well-known/openid-configuration", "OIDC discovery document",      MEDIUM),
    ("/.well-known/oauth-authorization-server", "OAuth AS metadata",     MEDIUM),
    ("/.well-known/change-password", "Password change well-known",        INFO),
    ("/.well-known/jwks.json",     "JSON Web Key Set",                   MEDIUM),
    ("/.well-known/ai-plugin.json", "ChatGPT/AI plugin manifest",        LOW),
    ("/.well-known/gpc.json",       "Global Privacy Control",             INFO),
    ("/.well-known/dnt-policy.txt", "Do Not Track policy",                INFO),
    ("/.well-known/traffic-advice", "Traffic advice (Chrome)",            INFO),
]


# ═════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS
# ═════════════════════════════════════════════════════════════════════════════

SECURITY_HEADERS: List[Tuple[str, str, str, str]] = [
    ("Strict-Transport-Security",
     "HSTS — forces HTTPS connections",
     HIGH, "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy",
     "CSP — restricts content sources to prevent XSS",
     HIGH, "default-src 'self'"),
    ("X-Frame-Options",
     "Prevents clickjacking via iframe embedding",
     MEDIUM, "DENY"),
    ("X-Content-Type-Options",
     "Prevents MIME-type sniffing",
     MEDIUM, "nosniff"),
    ("Referrer-Policy",
     "Controls referrer information sent with requests",
     LOW, "strict-origin-when-cross-origin"),
    ("Permissions-Policy",
     "Restricts browser feature access (camera, mic, etc.)",
     LOW, "geolocation=(), microphone=(), camera=()"),
    ("Cross-Origin-Opener-Policy",
     "Isolates browsing context from cross-origin windows",
     LOW, "same-origin"),
    ("Cross-Origin-Resource-Policy",
     "Prevents cross-origin loading of this resource",
     LOW, "same-origin"),
    ("Cross-Origin-Embedder-Policy",
     "Requires CORP for embedded sub-resources",
     LOW, "require-corp"),
]

DISCLOSURE_HEADERS: List[Tuple[str, str, str]] = [
    ("X-Powered-By",        "Reveals server technology/version", LOW),
    ("Server",              "Reveals web server software",       LOW),
    ("X-AspNet-Version",    "Reveals ASP.NET runtime version",   LOW),
    ("X-AspNetMvc-Version", "Reveals ASP.NET MVC version",       LOW),
    ("X-Generator",         "Reveals CMS or framework",          LOW),
    ("X-Drupal-Cache",      "Confirms Drupal CMS usage",         INFO),
    ("X-Varnish",           "Reveals Varnish cache server",      INFO),
]


# ═════════════════════════════════════════════════════════════════════════════
# WAF SIGNATURES
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: Dict[str, Dict] = {
    "Cloudflare": {
        "headers":  {"cf-ray", "cf-cache-status", "cf-request-id"},
        "cookies":  {"__cflb", "cf_clearance"},
        "server":   "cloudflare",
        "body":     ["Cloudflare Ray ID", "Attention Required! | Cloudflare"],
    },
    "Akamai": {
        "headers":  {"x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"},
        "cookies":  {"ak_bmsc", "bm_sz", "bm_sv"},
        "server":   None,
        "body":     ["Reference #", "Access Denied - Akamai"],
    },
    "Sucuri": {
        "headers":  {"x-sucuri-id", "x-sucuri-cache"},
        "cookies":  set(),
        "server":   "sucuri/cloudproxy",
        "body":     ["Access Denied - Sucuri Website Firewall"],
    },
    "Imperva / Incapsula": {
        "headers":  {"x-iinfo", "x-cdn"},
        "cookies":  {"incap_ses", "visid_incap"},
        "server":   None,
        "body":     ["Incapsula incident ID", "Request unsuccessful. Incapsula"],
    },
    "AWS WAF": {
        "headers":  {"x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"},
        "cookies":  {"aws-waf-token"},
        "server":   None,
        "body":     ["AWS WAF"],
    },
    "F5 BIG-IP ASM": {
        "headers":  {"x-wa-info", "x-cnection"},
        "cookies":  {"TS01", "BIGipServer"},
        "server":   "BigIP",
        "body":     ["The requested URL was rejected. Please consult with your administrator"],
    },
    "ModSecurity": {
        "headers":  set(),
        "cookies":  set(),
        "server":   None,
        "body":     ["Mod_Security", "ModSecurity", "406 Not Acceptable"],
    },
    "Wordfence": {
        "headers":  set(),
        "cookies":  {"wfvt_"},
        "server":   None,
        "body":     ["generated by Wordfence", "Wordfence Security"],
    },
    "Barracuda": {
        "headers":  {"x-barracuda-connect"},
        "cookies":  {"barra_counter_session"},
        "server":   None,
        "body":     ["Barracuda Web Application Firewall"],
    },
    "Fastly": {
        "headers":  {"x-fastly-request-id", "fastly-restarts", "x-served-by"},
        "cookies":  set(),
        "server":   "fastly",
        "body":     [],
    },
    "Nginx WAF": {
        "headers":  {"x-nf-request-id"},
        "cookies":  set(),
        "server":   None,
        "body":     [],
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# TECHNOLOGY FINGERPRINTS
# ═════════════════════════════════════════════════════════════════════════════

TECH_FINGERPRINTS: Dict[str, Dict] = {
    "WordPress": {
        "body":    ["/wp-content/", "/wp-includes/", "wp-emoji-release.min.js"],
        "headers": {},
        "cookies": ["wordpress_", "wp-settings-", "wordpress_logged_in_"],
        "meta":    [("generator", "WordPress")],
    },
    "Drupal": {
        "body":    ["/sites/default/files/", "Drupal.settings", "/misc/drupal.js"],
        "headers": {"x-drupal-cache": None, "x-generator": "Drupal"},
        "cookies": ["SESS", "SSESS"],
        "meta":    [("generator", "Drupal")],
    },
    "Joomla": {
        "body":    ["/media/jui/", "/components/com_"],
        "headers": {},
        "cookies": [],
        "meta":    [("generator", "Joomla")],
    },
    "Magento": {
        "body":    ["/skin/frontend/", "Mage.Cookies", "var BLANK_URL"],
        "headers": {},
        "cookies": ["frontend", "adminhtml"],
        "meta":    [],
    },
    "Shopify": {
        "body":    ["Shopify.theme", "cdn.shopify.com"],
        "headers": {"x-shopid": None, "x-shardid": None},
        "cookies": ["_session_id", "_shopify_visit"],
        "meta":    [],
    },
    "Laravel": {
        "body":    [],
        "headers": {},
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "meta":    [],
    },
    "Django": {
        "body":    [],
        "headers": {},
        "cookies": ["csrftoken", "sessionid"],
        "meta":    [],
    },
    "ASP.NET": {
        "body":    ["__VIEWSTATE", "__EVENTVALIDATION", "__RequestVerificationToken"],
        "headers": {"x-aspnet-version": None, "x-aspnetmvc-version": None},
        "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        "meta":    [],
    },
    "Ruby on Rails": {
        "body":    [],
        "headers": {"x-rack-cache": None, "x-runtime": None},
        "cookies": ["_session", "_rails"],
        "meta":    [],
    },
    "Next.js": {
        "body":    ["__NEXT_DATA__", "_next/static"],
        "headers": {"x-nextjs-cache": None},
        "cookies": [],
        "meta":    [],
    },
    "Nuxt.js": {
        "body":    ["__NUXT__", "_nuxt/"],
        "headers": {},
        "cookies": [],
        "meta":    [],
    },
    "React": {
        "body":    ["react.development.js", "react.production.min.js"],
        "headers": {},
        "cookies": [],
        "meta":    [],
    },
    "Angular": {
        "body":    ["ng-version=", "angular.min.js"],
        "headers": {},
        "cookies": [],
        "meta":    [],
    },
    "Vue.js": {
        "body":    ["vue.min.js", "__vue__"],
        "headers": {},
        "cookies": [],
        "meta":    [],
    },
    "jQuery": {
        "body":    ["jquery.min.js", "jquery-"],
        "headers": {},
        "cookies": [],
        "meta":    [],
    },
    "PHP": {
        "body":    [],
        "headers": {"x-powered-by": "PHP"},
        "cookies": ["PHPSESSID"],
        "meta":    [],
    },
    "Spring Boot": {
        "body":    [],
        "headers": {"x-application-context": None},
        "cookies": ["JSESSIONID"],
        "meta":    [],
    },
    "Supabase": {
        "body":    [
            ".supabase.co",
            "supabase.co/auth",
            "createClient(",
            "@supabase/supabase-js",
            'from("@supabase',
        ],
        "headers": {},
        "cookies": ["sb-access-token", "sb-refresh-token"],
        "meta":    [],
    },
    "Vercel": {
        "body":    ["vercel.live", "/_next/", "__NEXT_DATA__"],
        "headers": {"server": "vercel", "x-vercel-id": None, "x-vercel-cache": None},
        "cookies": [],
        "meta":    [],
    },
    "Netlify": {
        "body":    ["netlify.com", "netlify.app"],
        "headers": {"x-nf-request-id": None, "server": "netlify"},
        "cookies": [],
        "meta":    [],
    },
    "Cloudflare Pages": {
        "body":    [],
        "headers": {"cf-pages-project": None},
        "cookies": [],
        "meta":    [],
    },
    "Railway": {
        "body":    [".railway.app", "railway.app"],
        "headers": {},
        "cookies": [],
        "meta":    [],
    },
    "Render": {
        "body":    [".onrender.com"],
        "headers": {"x-render-routing": None},
        "cookies": [],
        "meta":    [],
    },
    "Fly.io": {
        "body":    [".fly.dev", "fly.io"],
        "headers": {"fly-request-id": None},
        "cookies": [],
        "meta":    [],
    },
}


def _decode_jwt_payload_segment(segment: str) -> Optional[dict]:
    """Decode a JWT payload segment (middle part) to JSON, or None."""
    try:
        s = segment.strip()
        pad = (4 - len(s) % 4) % 4
        if pad:
            s += "=" * pad
        raw = base64.urlsafe_b64decode(s.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# SCANNER
# ═════════════════════════════════════════════════════════════════════════════

class WebScanner:

    XSS_PROBE   = "WebScan7x3z"
    _JWT_TOKEN_RE = re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )
    _SUPABASE_HOST_RE = re.compile(
        r"https?://([a-z0-9_-]{10,40})\.supabase\.co", re.I
    )
    SSRF_PARAMS = frozenset([
        "url", "uri", "path", "src", "source", "dest", "destination",
        "redirect", "redirect_uri", "callback", "host", "fetch", "load",
        "proxy", "remote", "request", "image", "img", "file", "endpoint",
        "api", "target", "feed", "webhook", "ping", "import", "resource",
        "link", "href", "site", "domain", "open", "data", "ref",
    ])
    REDIRECT_PARAMS = frozenset([
        "redirect", "url", "next", "return", "returnurl", "redirect_uri",
        "goto", "target", "redir", "destination", "r", "u", "link",
        "forward", "callback", "continue", "location", "ref",
    ])
    COMMENT_KEYWORDS = frozenset([
        "password", "passwd", "secret", "api", "key", "token", "auth",
        "credential", "login", "admin", "debug", "todo", "fixme",
        "database", "db", "sql", "config", "private", "internal",
        "staging", "production", "hack", "temp", "disabled", "remove",
    ])
    CSRF_INDICATORS = frozenset([
        "csrf", "token", "_token", "authenticity_token",
        "__requestverificationtoken", "nonce", "xsrf", "_wpnonce",
    ])

    def __init__(
        self,
        target: str,
        timeout: int = 10,
        verify_ssl: bool = True,
        crawl: bool = False,
        depth: int = 1,
        threads: int = 10,
        rate_limit: float = 0.0,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        verbose: bool = False,
        internal_probes: bool = True,
        link_check: bool = True,
        link_check_max: int = 15,
    ):
        self.target     = target.rstrip("/")
        self.base_url   = self._get_base_url(target)
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.crawl      = crawl
        self.depth      = depth
        self.threads    = threads
        self.rate_limit = rate_limit
        self.proxy      = proxy
        self.verbose    = verbose
        self.internal_probes = internal_probes
        self.link_check    = link_check
        self._link_check_max = max(1, min(40, link_check_max))

        self.findings:      List[Finding] = []
        self.visited_urls:  Set[str]      = set()
        self._seen:         Set[str]      = set()
        self._lock          = threading.Lock()
        self._last_req_time = 0.0
        self._rate_lock     = threading.Lock()

        self.detected_tech:  Set[str]           = set()
        self.detected_waf:   Set[str]           = set()
        self._baseline_404:  Optional[Dict]     = None   # soft-404 fingerprint
        self._supabase_api_probed: Set[str]     = set()

        self.session = self._build_session(user_agent, proxy)

    # ── Session setup ─────────────────────────────────────────────────────────

    def _build_session(self, user_agent: Optional[str], proxy: Optional[str]) -> requests.Session:
        session = requests.Session()

        # Retry adapter
        retry = Retry(
            total=3,
            backoff_factor=0.4,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "OPTIONS", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://",  adapter)
        session.mount("https://", adapter)

        session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
            self._vprint(f"Proxy: {proxy}")

        return session

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_base_url(url: str) -> str:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _vprint(self, msg: str):
        if self.verbose:
            print(f"  {Fore.WHITE}[v] {msg}{Style.RESET_ALL}")

    def _add(self, f: Finding):
        key = f"{f.severity}|{f.title}|{f.evidence[:80]}"
        with self._lock:
            if key not in self._seen:
                self._seen.add(key)
                self.findings.append(f)

    def _throttle(self):
        if self.rate_limit <= 0:
            return
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_req_time
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_req_time = time.monotonic()

    def _get(self, url: str, extra_headers: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        self._throttle()
        try:
            h = dict(extra_headers) if extra_headers else {}
            return self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl,
                allow_redirects=True, headers=h, **kwargs,
            )
        except requests.exceptions.SSLError as e:
            self._add(Finding(
                severity=HIGH, category="SSL/TLS",
                title="SSL Certificate Error",
                description="Server SSL certificate could not be verified.",
                url=url, evidence=str(e)[:200],
                remediation="Install a valid certificate from a trusted CA.",
            ))
        except Exception as e:
            self._vprint(f"GET failed {url}: {e}")
        return None

    def _post(self, url: str, data: Optional[dict] = None, json_data=None,
              extra_headers: Optional[Dict] = None) -> Optional[requests.Response]:
        self._throttle()
        try:
            h = dict(extra_headers) if extra_headers else {}
            return self.session.post(
                url, data=data, json=json_data,
                timeout=self.timeout, verify=self.verify_ssl,
                allow_redirects=True, headers=h,
            )
        except Exception as e:
            self._vprint(f"POST failed {url}: {e}")
        return None

    # ═══════════════════════════════════════════════════════════════════════
    # SSL / TLS
    # ═══════════════════════════════════════════════════════════════════════

    def check_ssl(self):
        url    = self.target
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme != "https":
            self._add(Finding(
                severity=HIGH, category="SSL/TLS",
                title="Site Not Served Over HTTPS",
                description="Traffic is unencrypted and can be intercepted.",
                url=url, evidence=f"Scheme: {parsed.scheme}",
                remediation="Enable HTTPS and redirect all HTTP to HTTPS.",
            ))
            return

        host = parsed.hostname
        port = parsed.port or 443

        # Certificate check
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                cert = sock.getpeercert()

            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                now_utc   = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                days_left = (expire_dt - now_utc).days
                if days_left < 0:
                    self._add(Finding(severity=CRITICAL, category="SSL/TLS",
                        title="SSL Certificate Expired",
                        description=f"Certificate expired {abs(days_left)} day(s) ago.",
                        url=url, evidence=f"notAfter: {expire_str}",
                        remediation="Renew the SSL certificate immediately."))
                elif days_left < 14:
                    self._add(Finding(severity=CRITICAL, category="SSL/TLS",
                        title=f"SSL Certificate Expiring in {days_left} Day(s) — URGENT",
                        description="Less than 2 weeks until expiry.",
                        url=url, evidence=f"notAfter: {expire_str}",
                        remediation="Renew immediately."))
                elif days_left < 30:
                    self._add(Finding(severity=HIGH, category="SSL/TLS",
                        title=f"SSL Certificate Expiring in {days_left} Day(s)",
                        description="Certificate expires in under 30 days.",
                        url=url, evidence=f"notAfter: {expire_str}",
                        remediation="Renew the SSL certificate."))
                elif days_left < 90:
                    self._add(Finding(severity=MEDIUM, category="SSL/TLS",
                        title=f"SSL Certificate Expiring in {days_left} Day(s)",
                        description="Certificate expires in under 90 days.",
                        url=url, evidence=f"notAfter: {expire_str}",
                        remediation="Plan certificate renewal."))

        except ssl.SSLCertVerificationError as e:
            self._add(Finding(severity=CRITICAL, category="SSL/TLS",
                title="SSL Certificate Verification Failed",
                description="The server presents an invalid or untrusted certificate.",
                url=url, evidence=str(e)[:300],
                remediation="Install a valid certificate from a trusted CA."))
        except Exception:
            pass

        # TLS 1.0 / 1.1 detection
        self._check_old_tls(host, port, url)

    def _check_old_tls(self, host: str, port: int, url: str):
        # Use ssl.TLSVersion enum (Python 3.7+). PROTOCOL_TLSv1/TLSv1_1 are deprecated.
        for proto_name, tls_attr in [("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1")]:
            tls_ver = getattr(ssl.TLSVersion, tls_attr, None)
            if tls_ver is None:
                continue  # Not available on this platform/OpenSSL build
            try:
                # Suppress the deprecation warning — we're intentionally probing
                # for old protocol support, so using the deprecated enum is correct.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname  = False
                    ctx.verify_mode     = ssl.CERT_NONE
                    ctx.minimum_version = tls_ver
                    ctx.maximum_version = tls_ver

                with socket.create_connection((host, port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host):
                        self._add(Finding(
                            severity=HIGH, category="SSL/TLS",
                            title=f"Deprecated Protocol Accepted: {proto_name}",
                            description=f"Server accepts {proto_name}, which is cryptographically broken.",
                            url=url, evidence=f"Connection established using {proto_name}",
                            remediation=f"Disable {proto_name}. Require TLS 1.2 or higher.",
                        ))
            except Exception:
                pass   # Protocol rejected or unavailable — good

    # ═══════════════════════════════════════════════════════════════════════
    # SECURITY HEADERS
    # ═══════════════════════════════════════════════════════════════════════

    def check_security_headers(self, url: str, resp: requests.Response):
        lc = {k.lower(): v for k, v in resp.headers.items()}

        for header, desc, sev, recommended in SECURITY_HEADERS:
            if header.lower() not in lc:
                self._add(Finding(
                    severity=sev, category="Security Headers",
                    title=f"Missing Header: {header}",
                    description=desc + ".",
                    url=url, evidence=f"'{header}' not present in response",
                    remediation=f"{header}: {recommended}",
                ))

        for header, reason, sev in DISCLOSURE_HEADERS:
            val = lc.get(header.lower())
            if val:
                self._add(Finding(
                    severity=sev, category="Information Disclosure",
                    title=f"Verbose Header: {header}",
                    description=reason,
                    url=url, evidence=f"{header}: {val}",
                    remediation=f"Remove or suppress the '{header}' header.",
                ))

        # CORS
        acao = lc.get("access-control-allow-origin", "")
        acac = lc.get("access-control-allow-credentials", "").lower()
        if acao == "*":
            sev = CRITICAL if acac == "true" else MEDIUM
            self._add(Finding(
                severity=sev, category="CORS",
                title="Wildcard CORS" + (" + Credentials" if acac == "true" else ""),
                description="Any origin can read responses." + (
                    " With credentials: true, session tokens may be stolen." if acac == "true" else ""),
                url=url,
                evidence=f"Access-Control-Allow-Origin: {acao}" + (
                    f"\nAccess-Control-Allow-Credentials: {acac}" if acac else ""),
                remediation="Restrict CORS to explicit trusted origins.",
            ))

        # Weak CSP
        csp = lc.get("content-security-policy", "")
        if csp:
            unsafe = [d for d in ("'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'") if d in csp]
            if unsafe:
                self._add(Finding(
                    severity=MEDIUM, category="Security Headers",
                    title="Weak CSP: Unsafe Directives Present",
                    description=f"CSP uses {', '.join(unsafe)}, undermining XSS protection.",
                    url=url, evidence=f"Content-Security-Policy: {csp[:300]}",
                    remediation="Replace unsafe directives with nonces or hashes.",
                ))
            # Check for missing frame-ancestors (clickjacking via CSP)
            if "frame-ancestors" not in csp and "x-frame-options" not in lc:
                self._add(Finding(
                    severity=MEDIUM, category="Clickjacking",
                    title="No Clickjacking Protection (frame-ancestors / X-Frame-Options)",
                    description="Neither CSP frame-ancestors nor X-Frame-Options is set.",
                    url=url, evidence="Both headers absent",
                    remediation="Add Content-Security-Policy: frame-ancestors 'none'; or X-Frame-Options: DENY",
                ))

        # HSTS quality
        hsts = lc.get("strict-transport-security", "")
        if hsts:
            if "includesubdomains" not in hsts.lower():
                self._add(Finding(severity=LOW, category="Security Headers",
                    title="HSTS Missing includeSubDomains",
                    description="Subdomains not covered by HSTS policy.",
                    url=url, evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Add includeSubDomains to HSTS header."))
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 31_536_000:
                self._add(Finding(severity=LOW, category="Security Headers",
                    title="HSTS max-age Too Short",
                    description=f"max-age={m.group(1)} is below 1 year (31536000s).",
                    url=url, evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Set max-age to at least 31536000."))

        xrob = lc.get("x-robots-tag", "")
        if xrob and "noindex" in xrob.lower():
            self._add(Finding(
                severity=INFO, category="SEO / Indexing",
                title="X-Robots-Tag includes noindex",
                description="Search engines may omit this URL from indexes — common on staging.",
                url=url, evidence=f"X-Robots-Tag: {xrob}",
                remediation="Ensure production uses indexable directives when appropriate.",
            ))

        if url.startswith("https://") and "x-dns-prefetch-control" not in lc:
            self._add(Finding(
                severity=LOW, category="Security Headers",
                title="Missing X-DNS-Prefetch-Control",
                description="Without it, browsers may prefetch cross-origin links and leak intent.",
                url=url, evidence="Header absent on HTTPS response",
                remediation="Set X-DNS-Prefetch-Control: off (or on) explicitly.",
            ))

        if lc.get("report-to") or lc.get("nel"):
            self._add(Finding(
                severity=INFO, category="Observability",
                title="Network error / crash reporting headers present",
                description="Report-To and/or NEL can improve production diagnostics.",
                url=url,
                evidence="Report-To or NEL header set",
                remediation="Ensure endpoints are owned by your team and privacy-reviewed.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # CORS ADVANCED
    # ═══════════════════════════════════════════════════════════════════════

    def check_cors_advanced(self, url: str):
        for origin, label, null_sev in [
            ("https://evil-webscan-test.com", "Arbitrary Origin Reflected", HIGH),
        ]:
            try:
                r = self.session.get(url, timeout=self.timeout,
                                     verify=self.verify_ssl,
                                     headers={"Origin": origin},
                                     allow_redirects=True)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == origin:
                    sev = CRITICAL if acac == "true" else HIGH
                    self._add(Finding(
                        severity=sev, category="CORS",
                        title=f"CORS: {label}" + (" + Credentials" if acac == "true" else ""),
                        description="Server reflects arbitrary origins in ACAO header.",
                        url=url,
                        evidence=f"Sent Origin: {origin}\nGot ACAO: {acao}\nACAC: {acac}",
                        remediation="Validate Origin against an explicit allowlist.",
                    ))
            except Exception:
                pass

        # Null origin
        try:
            r = self.session.get(url, timeout=self.timeout,
                                 verify=self.verify_ssl,
                                 headers={"Origin": "null"},
                                 allow_redirects=True)
            if r.headers.get("Access-Control-Allow-Origin", "") == "null":
                self._add(Finding(
                    severity=HIGH, category="CORS",
                    title="CORS: Null Origin Accepted",
                    description="Server accepts Origin: null, allowing sandboxed iframes to bypass CORS.",
                    url=url, evidence="Access-Control-Allow-Origin: null",
                    remediation="Never trust the null origin.",
                ))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # COOKIE SECURITY
    # ═══════════════════════════════════════════════════════════════════════

    def check_cookie_security(self, url: str, resp: requests.Response):
        is_https = url.startswith("https://")
        raw: List[str] = []
        if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
            raw = resp.raw.headers.getlist("Set-Cookie")
        if not raw:
            sc = resp.headers.get("Set-Cookie")
            if sc:
                raw = [sc]

        for cs in raw:
            cl   = cs.lower()
            name = cs.split("=")[0].strip()
            issues: List[str] = []
            if "httponly" not in cl:
                issues.append("missing HttpOnly")
            if is_https and "secure" not in cl:
                issues.append("missing Secure")
            if "samesite" not in cl:
                issues.append("missing SameSite")
            if issues:
                self._add(Finding(
                    severity=MEDIUM, category="Cookie Security",
                    title=f"Insecure Cookie: {name}",
                    description="Cookie lacks security attributes.",
                    url=url,
                    evidence=f"Set-Cookie: {cs[:200]}\nIssues: {' | '.join(issues)}",
                    remediation="Set cookies with: Secure; HttpOnly; SameSite=Lax",
                ))

            if is_https and name.startswith("__Host-"):
                pfix: List[str] = []
                if "secure" not in cl:
                    pfix.append("__Host- requires Secure")
                if re.search(r"\bdomain\s*=", cl):
                    pfix.append("__Host- must not set Domain")
                if not re.search(r"path\s*=\s*/(?:;|$)", cl):
                    pfix.append("__Host- requires Path=/")
                if pfix:
                    self._add(Finding(
                        severity=MEDIUM, category="Cookie Security",
                        title=f"Invalid __Host- cookie: {name}",
                        description="RFC6265bis __Host- prefix rules violated.",
                        url=url,
                        evidence=f"Set-Cookie: {cs[:220]}\nIssues: {' | '.join(pfix)}",
                        remediation="Use Secure; Path=/; no Domain attribute for __Host- cookies.",
                    ))
            elif is_https and name.startswith("__Secure-") and "secure" not in cl:
                self._add(Finding(
                    severity=MEDIUM, category="Cookie Security",
                    title=f"Invalid __Secure- cookie: {name}",
                    description="__Secure- prefix requires the Secure attribute.",
                    url=url, evidence=f"Set-Cookie: {cs[:220]}",
                    remediation="Add the Secure flag to all __Secure- cookies.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # REDIRECT CHAIN (target URL, once per scan)
    # ═══════════════════════════════════════════════════════════════════════

    def check_redirect_chain(self) -> None:
        try:
            r = self.session.get(
                self.target, timeout=self.timeout, verify=self.verify_ssl,
                allow_redirects=True,
            )
        except Exception:
            return
        if not r.history:
            return
        hops: List[Tuple[int, str]] = [(x.status_code, x.url) for x in r.history]
        hops.append((r.status_code, r.url))
        tail = f" (+{len(hops) - 15} more hops)" if len(hops) > 15 else ""
        ev = " → ".join(f"{c} {u}" for c, u in hops[:15]) + tail

        if len(hops) > 10:
            self._add(Finding(
                severity=MEDIUM, category="HTTP",
                title="Long redirect chain",
                description=f"{len(hops)} hops before final response — slows navigation and complicates caching.",
                url=self.target, evidence=ev,
                remediation="Collapse redirects; prefer direct canonical URLs.",
            ))

        p0 = urllib.parse.urlparse(hops[0][1])
        pN = urllib.parse.urlparse(hops[-1][1])
        host0 = p0.netloc.split(":")[0].lower()
        hostN = pN.netloc.split(":")[0].lower()
        if p0.scheme == "http" and pN.scheme == "https" and host0 == hostN:
            self._add(Finding(
                severity=INFO, category="HTTP",
                title="HTTP upgraded to HTTPS via redirect",
                description="Users may briefly hit cleartext before the secure final URL.",
                url=self.target, evidence=ev,
                remediation="Use HTTPS links, HSTS, and HTTPS-by-default hosting.",
            ))
        if host0 != hostN:
            self._add(Finding(
                severity=LOW, category="HTTP",
                title="Redirect chain crosses hostnames",
                description="Different hosts in the chain affect cookies, CORS, and certificate validation.",
                url=self.target, evidence=ev,
                remediation="Document intentional cross-domain hops (CDN, auth, marketing).",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # HTTP TRANSPORT / CACHING (per response)
    # ═══════════════════════════════════════════════════════════════════════

    def check_http_transport(self, url: str, resp: requests.Response) -> None:
        elapsed = resp.elapsed.total_seconds()
        if elapsed >= 8.0:
            sev = HIGH
        elif elapsed >= 3.0:
            sev = MEDIUM
        else:
            sev = None
        if sev:
            self._add(Finding(
                severity=sev, category="Performance",
                title="Slow HTTP response",
                description="Total request time (connect + transfer) exceeded a typical UX threshold.",
                url=url, evidence=f"{elapsed:.2f}s (timeout setting: {self.timeout}s)",
                remediation="Profile TTFB, database, and edge caching; set performance budgets.",
            ))

        ce = (resp.headers.get("Content-Encoding") or "").lower()
        if ce.split(",")[0].strip() in ("gzip", "br", "deflate", "zstd"):
            enc = ce.split(",")[0].strip()
            self._add(Finding(
                severity=INFO, category="Performance",
                title=f"Response compressed ({enc})",
                description="Content-Encoding indicates on-the-wire compression.",
                url=url, evidence=f"Content-Encoding: {resp.headers.get('Content-Encoding', '')}",
                remediation="Keep compression enabled for text assets; avoid double compression.",
            ))

        ct = resp.headers.get("Content-Type", "").lower()
        hdr_lc = {k.lower() for k in resp.headers}
        if "text/html" in ct and "cache-control" not in hdr_lc:
            self._add(Finding(
                severity=LOW, category="Caching",
                title="HTML response has no Cache-Control",
                description="Browsers and CDNs must guess freshness; may hurt or help unintentionally.",
                url=url, evidence="Cache-Control header absent",
                remediation="Set explicit Cache-Control (and optionally stale-while-revalidate).",
            ))

        vary = resp.headers.get("Vary", "")
        if vary.strip() == "*":
            self._add(Finding(
                severity=LOW, category="Caching",
                title="Vary: * (hard to cache)",
                description="Shared caches cannot store this response efficiently.",
                url=url, evidence="Vary: *",
                remediation="Narrow Vary to specific request headers you actually vary on.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # DOCUMENT QUALITY (HTML smoke tests)
    # ═══════════════════════════════════════════════════════════════════════

    def check_document_quality(self, url: str, resp: requests.Response, soup: BeautifulSoup) -> None:
        if not soup.html:
            return

        head = resp.text.lstrip()[:400].upper()
        if not head.startswith("<!DOCTYPE"):
            self._add(Finding(
                severity=LOW, category="Frontend",
                title="Missing DOCTYPE",
                description="Without <!DOCTYPE html>, browsers may use quirks mode and inconsistent layout.",
                url=url, evidence=resp.text.lstrip()[:80].replace("\n", " "),
                remediation="Start documents with <!DOCTYPE html>.",
            ))

        lang = soup.html.get("lang") if soup.html else None
        if not (lang and str(lang).strip()):
            self._add(Finding(
                severity=LOW, category="Frontend",
                title="Missing html[lang]",
                description="Hurts accessibility and screen readers; impacts locale-aware features.",
                url=url, evidence="<html> without lang",
                remediation='Add lang="en" (or the primary page language).',
            ))

        viewport = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
        if not viewport:
            self._add(Finding(
                severity=MEDIUM, category="Frontend",
                title="Missing viewport meta tag",
                description="Mobile browsers may render desktop-width pages unreadably.",
                url=url, evidence="No <meta name=\"viewport\" …>",
                remediation='Add <meta name="viewport" content="width=device-width, initial-scale=1">.',
            ))

        canon = soup.find(
            "link",
            rel=lambda v: bool(v) and "canonical" in str(v).lower(),
            href=True,
        )
        if not canon:
            self._add(Finding(
                severity=LOW, category="SEO",
                title="No canonical link",
                description="Duplicate URLs may dilute SEO without a rel=canonical target.",
                url=url, evidence="No <link rel=\"canonical\" …>",
                remediation="Add a canonical URL for indexable pages.",
            ))

        h1s = soup.find_all("h1")
        if len(h1s) > 1:
            self._add(Finding(
                severity=LOW, category="SEO",
                title=f"Multiple <h1> elements ({len(h1s)})",
                description="Most style guides prefer a single top-level heading per view.",
                url=url, evidence=f"{len(h1s)} h1 tags",
                remediation="Use one h1; demote others to h2/h3.",
            ))

        if soup.title and soup.title.string:
            tl = soup.title.string.strip()
            if len(tl) == 0:
                self._add(Finding(
                    severity=MEDIUM, category="SEO",
                    title="Empty <title>",
                    description="Browser tabs and search results rely on a non-empty title.",
                    url=url, evidence="<title> is blank",
                    remediation="Set a concise, unique title per page.",
                ))
            elif len(tl) > 70:
                self._add(Finding(
                    severity=LOW, category="SEO",
                    title=f"Very long <title> ({len(tl)} characters)",
                    description="Search engines often truncate titles around ~60–70 characters.",
                    url=url, evidence=tl[:120] + ("…" if len(tl) > 120 else ""),
                    remediation="Shorten the title to the primary keywords and brand.",
                ))
        else:
            self._add(Finding(
                severity=MEDIUM, category="SEO",
                title="Missing <title>",
                description="No document title element found.",
                url=url, evidence="",
                remediation="Add a descriptive <title>.",
            ))

        robots = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
        rc = (robots.get("content") or "") if robots else ""
        if rc and "noindex" in rc.lower():
            self._add(Finding(
                severity=INFO, category="SEO / Indexing",
                title="meta robots contains noindex",
                description="This page asks crawlers not to index it.",
                url=url, evidence=f"content={rc[:120]}",
                remediation="Confirm staging vs production; remove noindex when the page should rank.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # INTERNAL LINK SAMPLE (HEAD)
    # ═══════════════════════════════════════════════════════════════════════

    def check_internal_link_health(self, page_url: str, soup: BeautifulSoup) -> None:
        if not self.link_check:
            return
        base_netloc = urllib.parse.urlparse(self.base_url).netloc
        seen: Set[str] = set()
        candidates: List[str] = []
        for tag in soup.find_all("a", href=True):
            href = (tag.get("href") or "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            abs_u = urllib.parse.urljoin(page_url, href).split("#")[0]
            if urllib.parse.urlparse(abs_u).netloc != base_netloc:
                continue
            if abs_u in seen:
                continue
            seen.add(abs_u)
            candidates.append(abs_u)
            if len(candidates) >= self._link_check_max:
                break

        for target in candidates:
            self._throttle()
            try:
                h = self.session.head(
                    target, timeout=min(8, self.timeout), verify=self.verify_ssl,
                    allow_redirects=True,
                )
                code = h.status_code
            except Exception:
                continue
            if code == 405:
                continue
            if code >= 400:
                sev = HIGH if code >= 500 else MEDIUM if code == 404 else LOW
                self._add(Finding(
                    severity=sev, category="Frontend / Links",
                    title=f"Internal link returned HTTP {code}",
                    description="HEAD request to an in-page anchor target did not succeed.",
                    url=target,
                    evidence=f"From: {page_url}\nHEAD → {code}",
                    remediation="Fix broken routes, trailing-slash rules, or remove dead links.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # HTTP METHODS
    # ═══════════════════════════════════════════════════════════════════════

    def check_http_methods(self, url: str):
        try:
            resp  = self.session.options(url, timeout=self.timeout, verify=self.verify_ssl)
            allow = resp.headers.get("Allow", "") or resp.headers.get("Public", "")
            if not allow:
                return
            dangerous = [m for m in ("PUT","DELETE","TRACE","CONNECT",
                                      "PROPFIND","PROPPATCH","MKCOL","MOVE","COPY")
                         if m in allow.upper()]
            if "TRACE" in allow.upper():
                self._add(Finding(severity=HIGH, category="HTTP Methods",
                    title="HTTP TRACE Enabled (XST Risk)",
                    description="TRACE can leak cookies via Cross-Site Tracing.",
                    url=url, evidence=f"Allow: {allow}",
                    remediation="Disable TRACE in your web server config."))
            rest = [m for m in dangerous if m != "TRACE"]
            if rest:
                self._add(Finding(severity=MEDIUM, category="HTTP Methods",
                    title=f"Dangerous HTTP Methods: {', '.join(rest)}",
                    description="Unnecessary methods increase the attack surface.",
                    url=url, evidence=f"Allow: {allow}",
                    remediation="Restrict to GET, POST, HEAD, OPTIONS."))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # HOST HEADER INJECTION
    # ═══════════════════════════════════════════════════════════════════════

    def check_host_header_injection(self, url: str):
        probe = "evil-webscan-host-inject.com"
        try:
            r = self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl,
                headers={"Host": probe, "X-Forwarded-Host": probe},
                allow_redirects=False,
            )
            body    = r.text
            headers = str(r.headers).lower()
            if probe in body or probe in headers:
                self._add(Finding(
                    severity=HIGH, category="Host Header Injection",
                    title="Host Header Injection Vulnerability",
                    description="Injected Host header was reflected in the response.",
                    url=url, evidence=f"Probe '{probe}' reflected in response body or headers",
                    remediation="Validate the Host header against a whitelist. Don't use Host for building URLs.",
                ))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # CRLF INJECTION
    # ═══════════════════════════════════════════════════════════════════════

    def check_crlf_injection(self, url: str):
        """
        Probe CRLF splitting via path and query. Payloads must stay inside the path or query
        so urllib/requests can parse the URL (appending %0d%0a directly to https://host
        without a '/' puts bytes in the host field and always fails with "Failed to parse").
        """
        payloads = [
            "%0d%0aX-Webscan-Injected:%201",
            "%0aX-Webscan-Injected:%201",
        ]
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if not path.endswith("/"):
            path = path + "/"
        path_base = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, path, "", "", "")
        )

        for payload in payloads:
            r = self._get(path_base + "webscan-crlf" + payload)
            if r and "X-Webscan-Injected" in r.headers:
                self._add(Finding(
                    severity=HIGH, category="CRLF Injection",
                    title="CRLF Injection Vulnerability",
                    description="Carriage return/line feed characters in the URL are not filtered, allowing header injection.",
                    url=path_base + "webscan-crlf" + payload,
                    evidence=f"Path payload: …webscan-crlf{payload[:40]}",
                    remediation="Strip or encode CRLF characters in all user-supplied input.",
                ))
                return

        q_base = url.split("#")[0]
        joiner = "&" if "?" in q_base else "?"
        for payload in payloads:
            test = f"{q_base}{joiner}webscan_r=x{payload}"
            r = self._get(test)
            if r and "X-Webscan-Injected" in r.headers:
                self._add(Finding(
                    severity=HIGH, category="CRLF Injection",
                    title="CRLF Injection Vulnerability",
                    description="CRLF in query parameters may split response headers.",
                    url=test,
                    evidence=f"Query payload: webscan_r=x{payload[:40]}",
                    remediation="Strip or encode CRLF characters in all user-supplied input.",
                ))
                return

    # ═══════════════════════════════════════════════════════════════════════
    # GRAPHQL INTROSPECTION
    # ═══════════════════════════════════════════════════════════════════════

    GRAPHQL_ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql",
                         "/graphql/v1", "/query", "/api/query"]

    def check_graphql(self):
        query = {"query": "{__schema{types{name}}}"}
        for ep in self.GRAPHQL_ENDPOINTS:
            url = self.base_url + ep
            r   = self._post(url, json_data=query,
                              extra_headers={"Content-Type": "application/json"})
            if r and r.status_code == 200 and "__schema" in r.text:
                self._add(Finding(
                    severity=MEDIUM, category="GraphQL",
                    title="GraphQL Introspection Enabled",
                    description="Introspection exposes the full API schema to attackers.",
                    url=url, evidence="__schema returned in response",
                    remediation="Disable introspection in production.",
                ))
                break

    # ═══════════════════════════════════════════════════════════════════════
    # ERROR PAGE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════

    ERROR_PAGE_PATTERNS = [
        (r"Traceback \(most recent call last\)",     "Python traceback exposed",        HIGH),
        (r"Exception in thread .+ main",             "Java exception trace exposed",    HIGH),
        (r"Fatal error:.*on line \d+",               "PHP fatal error with path",       HIGH),
        (r"Warning:.*on line \d+",                   "PHP warning with file path",      MEDIUM),
        (r"Microsoft.*ASP\.NET.*Error",              "ASP.NET error details",           MEDIUM),
        (r"at .+\(.+\.java:\d+\)",                   "Java stack trace exposed",        HIGH),
        (r"SQL syntax.*near",                        "SQL error details exposed",       HIGH),
        (r"You have an error in your SQL syntax",    "MySQL error exposed",             HIGH),
        (r"ORA-\d{5}:",                              "Oracle DB error exposed",         HIGH),
        (r"PostgreSQL.*ERROR:",                      "PostgreSQL error exposed",        HIGH),
        (r"sqlite3\.OperationalError",               "SQLite error exposed",            HIGH),
        (r"/home/[a-z_][a-z0-9_-]*/",               "Unix home directory path",        MEDIUM),
        (r"C:\\\\Users\\\\",                         "Windows user path",               MEDIUM),
        (r"C:\\\\inetpub\\\\",                       "IIS path disclosure",             MEDIUM),
        (r"mysql_query\s*\(",                        "MySQL function in response",      MEDIUM),
        (r"root:x:0:0:",                             "Unix /etc/passwd content",        CRITICAL),
    ]

    def check_error_pages(self):
        # Force a 404 with a random path
        rand = f"/webscan-probe-{int(time.time())}"
        for suffix in [rand, rand + ".php", rand + ".asp"]:
            url  = self.base_url + suffix
            resp = self._get(url)
            if not resp:
                continue
            for pattern, desc, sev in self.ERROR_PAGE_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self._add(Finding(
                        severity=sev, category="Information Disclosure",
                        title=f"Sensitive Info in Error Page: {desc}",
                        description="Error pages reveal internal implementation details.",
                        url=url, evidence=f"Pattern matched: {pattern}",
                        remediation="Configure custom error pages that don't reveal stack traces or paths.",
                    ))

    # ═══════════════════════════════════════════════════════════════════════
    # WAF DETECTION
    # ═══════════════════════════════════════════════════════════════════════

    def check_waf(self, resp: requests.Response):
        headers_lc  = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies_str = " ".join(c.name.lower() for c in resp.cookies)
        body        = resp.text[:5000].lower()
        server      = headers_lc.get("server", "")

        for name, sig in WAF_SIGNATURES.items():
            detected = False
            if any(h in headers_lc for h in sig.get("headers", set())):
                detected = True
            if any(c.lower() in cookies_str for c in sig.get("cookies", set())):
                detected = True
            if sig.get("server") and sig["server"].lower() in server:
                detected = True
            if any(b.lower() in body for b in sig.get("body", [])):
                detected = True
            if detected and name not in self.detected_waf:
                self.detected_waf.add(name)

    # ═══════════════════════════════════════════════════════════════════════
    # TECHNOLOGY FINGERPRINTING
    # ═══════════════════════════════════════════════════════════════════════

    def check_tech_stack(self, resp: requests.Response, soup: Optional[BeautifulSoup]):
        lc          = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies_str = " ".join(c.name.lower() for c in resp.cookies)
        body        = resp.text

        for tech, sig in TECH_FINGERPRINTS.items():
            if tech in self.detected_tech:
                continue
            matched = False
            if any(b in body for b in sig.get("body", [])):
                matched = True
            for hdr, val in sig.get("headers", {}).items():
                if hdr in lc and (val is None or val.lower() in lc[hdr]):
                    matched = True
            if any(c in cookies_str for c in sig.get("cookies", [])):
                matched = True
            if soup:
                for attr, val in sig.get("meta", []):
                    tag = soup.find("meta", attrs={attr: re.compile(val, re.I)})
                    if tag:
                        matched = True
            if matched:
                self.detected_tech.add(tech)

    # ═══════════════════════════════════════════════════════════════════════
    # JS FILE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════

    def check_js_files(self, page_url: str, soup: BeautifulSoup):
        js_urls: Set[str] = set()
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if src:
                js_urls.add(urllib.parse.urljoin(page_url, src))

        for js_url in list(js_urls)[:25]:
            resp = self._get(js_url)
            if not resp or resp.status_code != 200:
                continue

            # Scan for secrets
            self.check_secret_patterns(js_url, resp.text)
            self.check_supabase(js_url, resp.text)

            # Source map via header
            map_hdr = resp.headers.get("X-SourceMap") or resp.headers.get("SourceMap")
            if map_hdr:
                self._add(Finding(
                    severity=MEDIUM, category="Source Map Exposure",
                    title="Source Map Exposed via Header",
                    description="Source maps reveal original un-minified source code.",
                    url=js_url, evidence=f"X-SourceMap / SourceMap header: {map_hdr}",
                    remediation="Remove source maps from production builds.",
                ))

            # Source map via sourceMappingURL comment
            m = re.search(r"//[#@]\s*sourceMappingURL=(.+)$", resp.text, re.MULTILINE)
            if m:
                map_path = m.group(1).strip()
                if not map_path.startswith("data:"):
                    map_url  = urllib.parse.urljoin(js_url, map_path)
                    map_resp = self._get(map_url)
                    if map_resp and map_resp.status_code == 200:
                        self._add(Finding(
                            severity=MEDIUM, category="Source Map Exposure",
                            title="JavaScript Source Map Publicly Accessible",
                            description="Source maps expose original un-minified source code, logic, and comments.",
                            url=map_url,
                            evidence=f"sourceMappingURL={map_path}\nMap URL: {map_url}",
                            remediation="Exclude .map files from production deployment.",
                        ))

    # ═══════════════════════════════════════════════════════════════════════
    # SUBRESOURCE INTEGRITY
    # ═══════════════════════════════════════════════════════════════════════

    def check_sri(self, url: str, soup: BeautifulSoup):
        base_netloc   = urllib.parse.urlparse(url).netloc
        missing: List[str] = []
        for tag, attr in (("script", "src"), ("link", "href")):
            for elem in soup.find_all(tag):
                src = elem.get(attr, "")
                if not src:
                    continue
                parsed = urllib.parse.urlparse(src)
                if parsed.netloc and parsed.netloc != base_netloc:
                    if not elem.get("integrity"):
                        missing.append(f"<{tag} {attr}=\"{src[:80]}\">")
        if missing:
            self._add(Finding(
                severity=MEDIUM, category="Subresource Integrity",
                title="External Resources Loaded Without SRI",
                description=(
                    f"{len(missing)} external script(s)/stylesheet(s) lack integrity hashes. "
                    "A compromised CDN could inject malicious code."
                ),
                url=url,
                evidence="\n".join(missing[:6]) + (f"\n…and {len(missing)-6} more" if len(missing) > 6 else ""),
                remediation="Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to external resources.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # WORDPRESS
    # ═══════════════════════════════════════════════════════════════════════

    def check_wordpress(self):
        if "WordPress" not in self.detected_tech:
            return

        # User enumeration via REST API
        url  = self.base_url + "/wp-json/wp/v2/users"
        resp = self._get(url)
        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list) and users:
                    names = [u.get("slug") or u.get("name") or "?" for u in users[:10]]
                    self._add(Finding(
                        severity=HIGH, category="WordPress",
                        title="WordPress User Enumeration via REST API",
                        description="The REST API exposes a list of usernames.",
                        url=url, evidence=f"Users: {', '.join(names)}",
                        remediation="Disable user endpoint: remove_action('init', 'rest_api_init') or use a plugin.",
                    ))
            except Exception:
                pass

        # xmlrpc.php
        url  = self.base_url + "/xmlrpc.php"
        resp = self._get(url)
        if resp and resp.status_code == 200 and "XML-RPC" in resp.text:
            self._add(Finding(
                severity=MEDIUM, category="WordPress",
                title="WordPress XML-RPC Enabled",
                description="XML-RPC can be abused for brute-force amplification and SSRF.",
                url=url, evidence="HTTP 200 with XML-RPC content",
                remediation="Disable XML-RPC unless required. Add to .htaccess: deny from all",
            ))

        # wp-cron.php
        url  = self.base_url + "/wp-cron.php"
        resp = self._get(url)
        if resp and resp.status_code == 200:
            self._add(Finding(
                severity=LOW, category="WordPress",
                title="WordPress wp-cron.php Publicly Accessible",
                description="Can be used for DoS by triggering cron repeatedly.",
                url=url, evidence="HTTP 200",
                remediation="Add DISABLE_WP_CRON to wp-config.php and use server-side cron.",
            ))

        # Version disclosure in generator meta
        resp = self._get(self.target)
        if resp:
            m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', resp.text, re.I)
            if m:
                self._add(Finding(
                    severity=LOW, category="WordPress",
                    title=f"WordPress Version Disclosed: {m.group(1)}",
                    description="Version disclosure helps attackers target known CVEs.",
                    url=self.target, evidence=f"Generator meta: WordPress {m.group(1)}",
                    remediation="Remove the generator meta tag.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # SUPABASE
    # ═══════════════════════════════════════════════════════════════════════

    def check_supabase(self, url: str, content: str):
        """
        Detect Supabase project references, JWT roles (service_role vs anon),
        and probe REST / storage APIs when a project ref is discovered.
        """
        lc = content.lower()
        if (
            ".supabase.co" not in lc
            and "sb_secret_" not in content
            and "sb_publishable_" not in content
            and "supabase" not in lc
        ):
            return

        for m in self._SUPABASE_HOST_RE.finditer(content):
            ref = m.group(1).lower()
            self._add(Finding(
                severity=INFO,
                category="Supabase",
                title="Supabase project hostname referenced",
                description=(
                    "A *.supabase.co URL was found. The anon/publishable key is often embedded "
                    "in client apps; ensure Row Level Security (RLS) is enabled on all tables."
                ),
                url=url,
                evidence=f"https://{ref}.supabase.co",
                remediation="Review RLS policies, avoid exposing service_role or sb_secret_ keys in clients.",
            ))
            self._probe_supabase_public_api(ref)

        for token in set(self._JWT_TOKEN_RE.findall(content)):
            parts = token.split(".")
            if len(parts) != 3:
                continue
            payload = _decode_jwt_payload_segment(parts[1])
            if not payload or not isinstance(payload, dict):
                continue
            role = payload.get("role")
            iss  = str(payload.get("iss", "")).lower()
            if "supabase.co" not in iss:
                continue
            if role == "service_role":
                self._add(Finding(
                    severity=CRITICAL,
                    category="Supabase",
                    title="Supabase service_role JWT in source",
                    description=(
                        "Decoded JWT has role=service_role and a Supabase issuer. This key bypasses "
                        "RLS and must never ship to browsers or public repos."
                    ),
                    url=url,
                    evidence=f"iss={payload.get('iss', '')[:80]}… (token prefix: {token[:24]}…)",
                    remediation="Rotate the JWT secret in Supabase dashboard, revoke leaked keys, use only server-side.",
                ))
            elif role == "anon":
                self._add(Finding(
                    severity=INFO,
                    category="Supabase",
                    title="Supabase anon JWT in source",
                    description=(
                        "Public anon key detected (expected in many SPAs). Risk depends entirely on RLS: "
                        "without strict policies, data may be readable or writable by anyone."
                    ),
                    url=url,
                    evidence=f"iss={payload.get('iss', '')[:80]}",
                    remediation="Audit RLS for every table; never rely on hiding the anon key.",
                ))

    def _probe_supabase_public_api(self, project_ref: str):
        if project_ref in self._supabase_api_probed:
            return
        self._supabase_api_probed.add(project_ref)
        base = f"https://{project_ref}.supabase.co"

        rest_url = base + "/rest/v1/"
        r = self._get(rest_url)
        if r and r.status_code == 200:
            body = (r.text or "").strip().lower()
            if any(x in body for x in ("jwt", "unauthorized", "permission denied", "invalid", "apikey")):
                return
            if len(r.text or "") > 80 and (
                (r.text or "").strip().startswith("[")
                or '"definitions"' in (r.text or "")
                or "/rest/v1/" in (r.text or "")[:200]
            ):
                self._add(Finding(
                    severity=HIGH,
                    category="Supabase",
                    title="Supabase REST root returned 200 without obvious auth error",
                    description=(
                        "GET /rest/v1/ returned HTTP 200 with a body that does not look like a standard "
                        "unauthenticated error. This may indicate a misconfiguration — verify manually."
                    ),
                    url=rest_url,
                    evidence=(r.text or "")[:400],
                    remediation="Ensure PostgREST requires a valid API key/JWT for all routes.",
                ))

        st_url = base + "/storage/v1/bucket"
        s = self._get(st_url)
        if s and s.status_code == 200 and s.text:
            try:
                data = json.loads(s.text)
            except json.JSONDecodeError:
                return
            if isinstance(data, list) and len(data) > 0:
                self._add(Finding(
                    severity=HIGH,
                    category="Supabase",
                    title="Supabase Storage bucket list may be public",
                    description=(
                        "GET /storage/v1/bucket returned a JSON array without authentication. "
                        "Public bucket enumeration can expose storage layout."
                    ),
                    url=st_url,
                    evidence=json.dumps(data[:5], default=str)[:400],
                    remediation="Review storage bucket policies; avoid public list unless intended.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # SECRET PATTERNS
    # ═══════════════════════════════════════════════════════════════════════

    def check_secret_patterns(self, url: str, content: str):
        for name, pattern, sev in SECRET_PATTERNS:
            try:
                matches = re.findall(pattern, content)
            except re.error:
                continue
            for match in matches:
                ev = match if isinstance(match, str) else (match[0] if match else "")
                if not ev:
                    continue
                self._add(Finding(
                    severity=sev, category="Exposed Secrets",
                    title=f"Possible {name} Exposed",
                    description=f"Pattern matching a {name} was found in the page.",
                    url=url,
                    evidence=(ev[:120] + "…" if len(ev) > 120 else ev),
                    remediation=f"Remove and rotate/revoke the {name} immediately.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # HTML COMMENTS
    # ═══════════════════════════════════════════════════════════════════════

    def check_html_comments(self, url: str, soup: BeautifulSoup):
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            if len(text) < 5:
                continue
            matched = [kw for kw in self.COMMENT_KEYWORDS if kw in text.lower()]
            if matched:
                self._add(Finding(
                    severity=LOW, category="Information Disclosure",
                    title="Sensitive Keywords in HTML Comment",
                    description=f"Keywords found: {', '.join(sorted(matched))}",
                    url=url, evidence=text[:400],
                    remediation="Strip sensitive comments before production deployment.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # MIXED CONTENT
    # ═══════════════════════════════════════════════════════════════════════

    def check_mixed_content(self, url: str, soup: BeautifulSoup):
        if not url.startswith("https://"):
            return
        items: List[str] = []
        for tag, attr in (("script","src"),("link","href"),("img","src"),
                           ("iframe","src"),("audio","src"),("video","src"),
                           ("source","src"),("form","action")):
            for elem in soup.find_all(tag):
                res = elem.get(attr, "")
                if isinstance(res, str) and res.startswith("http://"):
                    items.append(f"<{tag} {attr}=\"{res[:80]}\">")
        if items:
            shown = items[:6]
            self._add(Finding(
                severity=MEDIUM, category="Mixed Content",
                title="HTTP Resources on HTTPS Page",
                description="Insecure resources can be intercepted/tampered.",
                url=url,
                evidence="\n".join(shown) + (f"\n…{len(items)-6} more" if len(items) > 6 else ""),
                remediation="Update all resource URLs to HTTPS.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # FORMS (CSRF / autocomplete)
    # ═══════════════════════════════════════════════════════════════════════

    def check_forms(self, url: str, soup: BeautifulSoup):
        for form in soup.find_all("form"):
            method = form.get("method", "get").lower()
            action = form.get("action", "")
            # External form action
            if action:
                abs_action = urllib.parse.urljoin(url, action)
                if urllib.parse.urlparse(abs_action).netloc not in ("", urllib.parse.urlparse(url).netloc):
                    self._add(Finding(
                        severity=HIGH, category="Form Security",
                        title="Form Action Points to External Domain",
                        description="Data submitted via this form goes to a third-party domain.",
                        url=url,
                        evidence=f"<form action=\"{action}\" method=\"{method}\">",
                        remediation="Verify the external domain is intentional and trusted.",
                    ))
            if method == "post":
                inputs      = form.find_all("input")
                input_names = [i.get("name", "").lower() for i in inputs]
                has_csrf    = any(
                    any(ind in n for ind in self.CSRF_INDICATORS)
                    for n in input_names
                )
                if not has_csrf:
                    self._add(Finding(
                        severity=MEDIUM, category="CSRF",
                        title="POST Form Possibly Missing CSRF Token",
                        description="No visible CSRF token found in a state-changing form.",
                        url=url,
                        evidence=f"<form action=\"{action}\" method=\"post\">\nFields: {', '.join(input_names[:12])}",
                        remediation="Add a CSRF token to all state-changing forms.",
                    ))
            # Password autocomplete
            for inp in form.find_all("input", {"type": "password"}):
                ac = inp.get("autocomplete", "on").lower()
                if ac not in ("off", "new-password", "current-password"):
                    self._add(Finding(
                        severity=LOW, category="Form Security",
                        title="Password Field Allows Browser Autocomplete",
                        description="Browser may save the password.",
                        url=url, evidence=str(inp)[:200],
                        remediation="Set autocomplete=\"new-password\" on password fields.",
                    ))

    # ═══════════════════════════════════════════════════════════════════════
    # OPEN REDIRECT / SSRF PARAMS
    # ═══════════════════════════════════════════════════════════════════════

    def check_redirect_and_ssrf_params(self, url: str):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for param, values in qs.items():
            pl = param.lower()
            if pl in self.REDIRECT_PARAMS:
                self._add(Finding(
                    severity=MEDIUM, category="Open Redirect",
                    title=f"Possible Open Redirect Parameter: '{param}'",
                    description="Redirect parameter may allow sending users to malicious URLs.",
                    url=url, evidence=f"?{param}={values[0]}",
                    remediation="Validate redirect destinations against an allowlist.",
                ))
            if pl in self.SSRF_PARAMS:
                self._add(Finding(
                    severity=MEDIUM, category="SSRF",
                    title=f"Possible SSRF-Prone Parameter: '{param}'",
                    description="Parameter name commonly associated with Server-Side Request Forgery.",
                    url=url, evidence=f"?{param}={values[0]}",
                    remediation="Restrict URLs to trusted hosts. Block internal IP ranges.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # REFLECTED PARAMS (basic XSS detection)
    # ═══════════════════════════════════════════════════════════════════════

    def check_reflected_params(self, url: str):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return
        for param in list(qs.keys())[:5]:
            new_qs  = dict(qs)
            new_qs[param] = [self.XSS_PROBE]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs, doseq=True))
            )
            resp = self._get(test_url)
            if resp and self.XSS_PROBE in resp.text:
                self._add(Finding(
                    severity=HIGH, category="XSS",
                    title=f"Parameter '{param}' Reflected Without Encoding",
                    description="Input echoed in response without HTML encoding — possible XSS.",
                    url=test_url,
                    evidence=f"Probe '{self.XSS_PROBE}' reflected in response for ?{param}=...",
                    remediation="HTML-encode all user-controlled output. Implement a strict CSP.",
                ))

    # ═══════════════════════════════════════════════════════════════════════
    # EMAIL HARVESTING
    # ═══════════════════════════════════════════════════════════════════════

    EMAIL_FP_DOMAINS = frozenset([
        "example.com", "domain.com", "yourdomain.com", "sentry.io",
        "schema.org", "w3.org", "jquery.com", "google.com", "github.com",
        "email.com", "test.com", "foo.com", "bar.com",
    ])

    def check_emails(self, url: str, content: str):
        emails = set(re.findall(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', content))
        real   = [e for e in emails
                  if not any(fp in e.lower() for fp in self.EMAIL_FP_DOMAINS)
                  and len(e) < 100]
        if real:
            self._add(Finding(
                severity=LOW, category="Information Disclosure",
                title=f"Email Address(es) Exposed in Page Source ({len(real)})",
                description="Exposed emails may be used for phishing or spam.",
                url=url, evidence="\n".join(sorted(real)[:10]),
                remediation="Use contact forms. Obfuscate emails if they must be shown.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # DIRECTORY LISTING
    # ═══════════════════════════════════════════════════════════════════════

    DIR_MARKERS = ("Index of /", "Directory listing for",
                   "Parent Directory", "[To Parent Directory]", "<title>Index of")

    def check_directory_listing(self, url: str, resp: requests.Response):
        for m in self.DIR_MARKERS:
            if m in resp.text:
                self._add(Finding(
                    severity=HIGH, category="Directory Listing",
                    title="Directory Listing Enabled",
                    description="Web server exposes directory contents.",
                    url=url, evidence=f"Contains: '{m}'",
                    remediation="Disable: Options -Indexes (Apache) or autoindex off (nginx).",
                ))
                break

    # ═══════════════════════════════════════════════════════════════════════
    # ROBOTS.TXT
    # ═══════════════════════════════════════════════════════════════════════

    ROBOTS_KEYWORDS = ("admin","config","backup","db","database","secret",
                       "private","api","internal","debug","staging","test",
                       "password","auth","login","credentials","hidden")

    def check_robots_txt(self):
        url  = self.base_url + "/robots.txt"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return
        # Deduplicate: robots.txt often has identical Disallow lines repeated
        # across multiple User-agent blocks (Googlebot, Bingbot, *, …)
        disallowed = list(dict.fromkeys(
            line.split(":", 1)[1].strip()
            for line in resp.text.splitlines()
            if line.lower().startswith("disallow:") and ":" in line
        ))
        sensitive = [p for p in disallowed
                     if any(kw in p.lower() for kw in self.ROBOTS_KEYWORDS)]
        if sensitive:
            self._add(Finding(
                severity=LOW, category="Information Disclosure",
                title="Sensitive Paths in robots.txt",
                description="Disallow entries hint at sensitive paths.",
                url=url, evidence="\n".join(sensitive[:20]),
                remediation="Remove sensitive entries. Protect paths properly.",
            ))

    # ═══════════════════════════════════════════════════════════════════════
    # SOFT-404 BASELINE  (SPA / catch-all route detection)
    # ═══════════════════════════════════════════════════════════════════════

    # Extensions that should never legitimately return text/html.
    # A real .xml or .txt file is served as text/xml or text/plain;
    # getting text/html back means the server is routing the request
    # to its SPA / catch-all handler.
    _NON_HTML_EXTS = frozenset([
        ".sql", ".env", ".json", ".yml", ".yaml", ".pem", ".key",
        ".zip", ".tar", ".gz", ".bak", ".conf", ".cfg", ".ini",
        ".db", ".sqlite", ".sh", ".bash", ".htpasswd", ".netrc",
        ".npmrc", ".pypirc", ".rb", ".py", ".java", ".class",
        # Added: xml/txt files are never legitimately served as HTML
        ".xml", ".txt", ".csv", ".log", ".md",
    ])

    # Paths whose real responses must be non-HTML (JSON / Prometheus text / etc.).
    # If one of these returns text/html it is a soft-404, not a real finding.
    _NON_HTML_PATHS = frozenset([
        "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
        "/api-docs", "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/metrics",
        "/_cat/indices", "/_cluster/health",
        "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/actuator/heapdump", "/actuator/httptrace", "/actuator/logfile",
    ])

    def _establish_404_baseline(self) -> None:
        """
        Fetch two random nonexistent paths and record their fingerprint.
        Sites that return HTTP 200 for everything (SPAs, catch-all routes)
        will produce consistent responses that we can later recognise as
        soft-404s and skip, eliminating false positives.
        """
        ts = int(time.time())
        # Use diverse probe patterns so we detect soft-404 behaviour regardless
        # of whether the router only catches plain paths, API paths, dot-files, etc.
        probes = [
            f"/webscan-404-baseline-{ts}-rand",          # plain unknown path
            f"/webscan-404-baseline-{ts}-rand.php",      # file-extension variant
            f"/api/webscan-404-baseline-{ts}",           # API-looking path
            f"/.webscan-404-baseline-{ts}",              # dot-file pattern
        ]
        sizes:  List[int] = []
        hashes: Set[str]  = set()
        ct_base: Optional[str] = None

        for path in probes:
            resp = self._get(self.base_url + path)
            if resp is None or resp.status_code != 200 or len(resp.content) == 0:
                continue
            ct   = resp.headers.get("Content-Type", "").split(";")[0].strip()
            size = len(resp.content)
            h    = hashlib.md5(resp.content).hexdigest()
            sizes.append(size)
            hashes.add(h)
            if ct_base is None:
                ct_base = ct

        if not sizes:
            self._baseline_404 = None   # server returns proper 404s — no filter needed
            return

        # Allow ±25% size variance to handle paths embedded in the response body
        # (SPAs often echo the requested path in a <title> or JSON blob)
        margin = max(1000, int(max(sizes) * 0.25))
        self._baseline_404 = {
            "ct":       ct_base,
            "size_min": min(sizes) - margin,
            "size_max": max(sizes) + margin,
            "hashes":   hashes,
        }
        self._vprint(
            f"Soft-404 detected: CT={ct_base}, "
            f"size≈{min(sizes)}-{max(sizes)} bytes (±{margin}). "
            f"Filtering matching responses."
        )

    def _is_soft_404(self, resp: requests.Response, path: str) -> bool:
        """
        Return True if this response is indistinguishable from a soft-404:
          1. Body hash matches one of the baseline probes (exact duplicate)
          2. Content-Type + size fall within the baseline window
          3. Response is text/html but path carries a non-HTML extension
             (real .sql / .env / .pem files are never served as HTML)
        """
        ct   = resp.headers.get("Content-Type", "").split(";")[0].strip()
        size = len(resp.content)

        # Rule 3a — extension check (no baseline required)
        # Real config/data files are never served as text/html
        last_seg = path.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        ext = ("." + last_seg.rsplit(".", 1)[-1].lower()) if "." in last_seg else ""
        if ct == "text/html" and ext in self._NON_HTML_EXTS:
            return True

        # Rule 3b — known data-only paths (no baseline required)
        # e.g. /graphql, /api-docs, /metrics must return JSON/Prometheus, not HTML
        if ct == "text/html" and path in self._NON_HTML_PATHS:
            return True

        b = self._baseline_404
        if b is None:
            return False

        # Rule 1 — exact hash match
        if hashlib.md5(resp.content).hexdigest() in b["hashes"]:
            return True

        # Rule 2 — same content-type, size within the baseline window
        if ct == b["ct"] and b["size_min"] <= size <= b["size_max"]:
            return True

        return False

    # ═══════════════════════════════════════════════════════════════════════
    # PATH PROBING (sensitive files + dev/ops routes)
    # ═══════════════════════════════════════════════════════════════════════

    def _probe_path_batch(
        self,
        paths: List[Tuple[str, str, str]],
        *,
        category: str,
        title_ok: str,
        remediation_200: str,
        forbidden_403: Optional[Tuple[str, ...]] = None,
    ) -> None:
        def probe(item: Tuple[str, str, str]) -> None:
            path, desc, sev = item
            url  = self.base_url + path
            resp = self._get(url)
            if not resp:
                return

            if resp.status_code == 200 and len(resp.content) > 0:
                if self._is_soft_404(resp, path):
                    self._vprint(f"Soft-404 (skipped): {path}")
                    return
                ct   = resp.headers.get("Content-Type", "")
                size = len(resp.content)
                self._add(Finding(
                    severity=sev, category=category,
                    title=f"{title_ok}: {path}",
                    description=desc,
                    url=url, evidence=f"HTTP 200 — {ct} — {size} bytes",
                    remediation=remediation_200.format(path=path),
                ))
            elif (
                forbidden_403
                and resp.status_code == 403
                and path in forbidden_403
            ):
                self._add(Finding(
                    severity=LOW, category=category,
                    title=f"Sensitive Path Exists (403): {path}",
                    description=f"{desc} — path confirmed, access restricted.",
                    url=url, evidence="HTTP 403",
                    remediation="Confirm this file cannot be read from the internet.",
                ))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, paths))

    def check_sensitive_files(self) -> None:
        self._establish_404_baseline()

        print(f"\n{Fore.CYAN}[*] Probing {len(SENSITIVE_FILES)} sensitive paths "
              f"({self.threads} threads)...{Style.RESET_ALL}")

        self._probe_path_batch(
            SENSITIVE_FILES,
            category="Exposed Files",
            title_ok="Accessible",
            remediation_200="Block or move {path} outside the web root.",
            forbidden_403=(
                "/.env", "/.git/config", "/.htpasswd", "/.ssh/id_rsa", "/wp-config.php",
            ),
        )

    def check_dev_and_ops_paths(self) -> None:
        if not self.internal_probes:
            return
        print(f"\n{Fore.CYAN}[*] Probing {len(DEV_AND_OBSERVABILITY_PATHS)} dev/health/API paths "
              f"({self.threads} threads)...{Style.RESET_ALL}")
        self._probe_path_batch(
            DEV_AND_OBSERVABILITY_PATHS,
            category="Dev / Ops",
            title_ok="Reachable",
            remediation_200="Confirm `{path}` is intentional for this environment; remove or auth-guard in production.",
            forbidden_403=None,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # LINK COLLECTOR
    # ═══════════════════════════════════════════════════════════════════════

    def _collect_links(self, page_url: str, soup: BeautifulSoup) -> Set[str]:
        base_netloc = urllib.parse.urlparse(self.base_url).netloc
        links: Set[str] = set()
        for tag in soup.find_all(["a", "link", "form"]):
            href = tag.get("href") or tag.get("action") or ""
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            abs_url = urllib.parse.urljoin(page_url, href).split("#")[0]
            if urllib.parse.urlparse(abs_url).netloc == base_netloc:
                links.add(abs_url)
        return links

    # ═══════════════════════════════════════════════════════════════════════
    # SINGLE URL SCAN
    # ═══════════════════════════════════════════════════════════════════════

    def scan_url(self, url: str) -> Optional[BeautifulSoup]:
        if url in self.visited_urls:
            return None
        self.visited_urls.add(url)
        print(f"  {Fore.WHITE}→ {url}{Style.RESET_ALL}")

        resp = self._get(url)
        if not resp:
            return None

        self.check_waf(resp)
        self.check_http_transport(url, resp)
        self.check_security_headers(url, resp)
        self.check_cookie_security(url, resp)
        self.check_http_methods(url)
        self.check_directory_listing(url, resp)
        self.check_secret_patterns(url, resp.text)
        self.check_supabase(url, resp.text)
        self.check_redirect_and_ssrf_params(url)
        self.check_reflected_params(url)
        self.check_emails(url, resp.text)

        if "html" not in resp.headers.get("Content-Type", ""):
            return None

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return None

        self.check_tech_stack(resp, soup)
        self.check_document_quality(url, resp, soup)
        self.check_html_comments(url, soup)
        self.check_mixed_content(url, soup)
        self.check_forms(url, soup)
        self.check_sri(url, soup)
        self.check_js_files(url, soup)
        self.check_internal_link_health(url, soup)
        return soup

    # ═══════════════════════════════════════════════════════════════════════
    # MAIN RUN
    # ═══════════════════════════════════════════════════════════════════════

    def run(self) -> List[Finding]:
        proxy_info = f"  Proxy   : {self.proxy}" if self.proxy else ""
        dev_line = (
            f"  Dev QA  : internal path probes={'on' if self.internal_probes else 'off'}  |  "
            f"link HEAD check={'on' if self.link_check else 'off'} "
            f"(max {self._link_check_max}/page)"
        )
        print(f"""
{Fore.CYAN}{'═'*64}
  WebScan v2 — Advanced Website Security Scanner
{'═'*64}{Style.RESET_ALL}
  Target  : {self.target}
  Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Crawl   : {'Yes (depth=' + str(self.depth) + ')' if self.crawl else 'No'}
  Threads : {self.threads}  |  Rate limit: {self.rate_limit}s{(chr(10) + proxy_info) if proxy_info else ''}
{dev_line}
{Fore.CYAN}{'═'*64}{Style.RESET_ALL}""")

        print(f"{Fore.CYAN}[*] SSL/TLS...{Style.RESET_ALL}")
        self.check_ssl()

        print(f"{Fore.CYAN}[*] Redirect chain...{Style.RESET_ALL}")
        self.check_redirect_chain()

        print(f"{Fore.CYAN}[*] robots.txt...{Style.RESET_ALL}")
        self.check_robots_txt()

        print(f"{Fore.CYAN}[*] GraphQL introspection...{Style.RESET_ALL}")
        self.check_graphql()

        print(f"{Fore.CYAN}[*] Error page analysis...{Style.RESET_ALL}")
        self.check_error_pages()

        print(f"{Fore.CYAN}[*] Host header injection...{Style.RESET_ALL}")
        self.check_host_header_injection(self.target)

        print(f"{Fore.CYAN}[*] CRLF injection...{Style.RESET_ALL}")
        self.check_crlf_injection(self.target)

        print(f"{Fore.CYAN}[*] CORS advanced...{Style.RESET_ALL}")
        self.check_cors_advanced(self.target)

        self.check_sensitive_files()
        self.check_dev_and_ops_paths()

        print(f"\n{Fore.CYAN}[*] Scanning pages...{Style.RESET_ALL}")
        queue = {self.target}
        d     = 0
        while queue and d <= self.depth:
            nxt: Set[str] = set()
            for url in queue:
                soup = self.scan_url(url)
                if soup and self.crawl and d < self.depth:
                    nxt |= self._collect_links(url, soup) - self.visited_urls
            queue = nxt
            d    += 1

        # WordPress-specific (after tech detection)
        if "WordPress" in self.detected_tech:
            print(f"{Fore.CYAN}[*] WordPress checks...{Style.RESET_ALL}")
            self.check_wordpress()

        return self.findings

    # ═══════════════════════════════════════════════════════════════════════
    # TERMINAL REPORT
    # ═══════════════════════════════════════════════════════════════════════

    def print_report(self, min_severity: str = INFO):
        min_ord = SEVERITY_ORDER.get(min_severity, 99)
        shown   = sorted(
            [f for f in self.findings if SEVERITY_ORDER.get(f.severity, 99) <= min_ord],
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )

        print(f"\n{Fore.CYAN}{'═'*64}")
        print("  SCAN COMPLETE")
        print(f"{'═'*64}{Style.RESET_ALL}\n")

        # WAF / Tech detected
        if self.detected_waf:
            print(f"  {Fore.YELLOW}WAF Detected  : {', '.join(sorted(self.detected_waf))}{Style.RESET_ALL}")
        if self.detected_tech:
            print(f"  {Fore.WHITE}Technologies  : {', '.join(sorted(self.detected_tech))}{Style.RESET_ALL}")
        print()

        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1

        for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
            n = counts[sev]
            if n:
                c = SEVERITY_COLOR[sev]
                print(f"  {c}[{sev:<8}]{Style.RESET_ALL} {n:>4}  {'█' * min(n, 40)}")

        print(f"\n  Total findings : {len(self.findings)}")
        print(f"  URLs scanned   : {len(self.visited_urls)}")

        if not shown:
            print(f"\n{Fore.GREEN}  No findings at or above '{min_severity}' severity.{Style.RESET_ALL}\n")
            return

        print(f"\n{Fore.CYAN}{'─'*64}{Style.RESET_ALL}\n")
        for i, f in enumerate(shown, 1):
            c = SEVERITY_COLOR.get(f.severity, Fore.WHITE)
            print(f"{c}[{f.severity}] #{i:03d}{Style.RESET_ALL}  {Style.BRIGHT}{f.title}{Style.RESET_ALL}")
            print(f"         Category    : {f.category}")
            print(f"         URL         : {f.url}")
            if f.description:
                print(f"         Description : {f.description}")
            if f.evidence:
                lines = f.evidence.splitlines()
                print(f"         Evidence    : {lines[0]}")
                for line in lines[1:]:
                    print(f"                       {line}")
            if f.remediation:
                print(f"         Fix         : {f.remediation}")
            print()

    # ═══════════════════════════════════════════════════════════════════════
    # JSON REPORT
    # ═══════════════════════════════════════════════════════════════════════

    def save_json(self, path: str):
        out = {
            "scan_info": {
                "target": self.target, "proxy": self.proxy,
                "timestamp": datetime.datetime.now().isoformat(),
                "urls_scanned": sorted(self.visited_urls),
                "total_findings": len(self.findings),
                "waf_detected": sorted(self.detected_waf),
                "tech_detected": sorted(self.detected_tech),
                "internal_probes": self.internal_probes,
                "link_check": self.link_check,
                "link_check_max": self._link_check_max,
            },
            "summary": {sev: sum(1 for f in self.findings if f.severity == sev)
                        for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO)},
            "findings": [f.to_dict() for f in
                         sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"{Fore.GREEN}[+] JSON report → {path}{Style.RESET_ALL}")

    # ═══════════════════════════════════════════════════════════════════════
    # HTML REPORT
    # ═══════════════════════════════════════════════════════════════════════

    def save_html(self, path: str):
        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        counts = {sev: sum(1 for f in self.findings if f.severity == sev)
                  for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO)}

        def badge(sev: str) -> str:
            color = SEVERITY_HTML.get(sev, "#6b7280")
            return f'<span class="badge" style="background:{color}">{html_module.escape(sev)}</span>'

        def card(i: int, f: Finding) -> str:
            color    = SEVERITY_HTML.get(f.severity, "#6b7280")
            ev_html  = html_module.escape(f.evidence).replace("\n", "<br>")
            return f"""
            <div class="finding" data-sev="{f.severity}" data-cat="{html_module.escape(f.category)}">
              <div class="finding-header" onclick="toggle(this)" style="border-left:4px solid {color}">
                <span>{badge(f.severity)} <strong>#{i:03d} — {html_module.escape(f.title)}</strong></span>
                <span class="cat">{html_module.escape(f.category)}</span>
              </div>
              <div class="finding-body" style="display:none">
                <table>
                  <tr><th>URL</th><td><a href="{html_module.escape(f.url)}" target="_blank">{html_module.escape(f.url)}</a></td></tr>
                  <tr><th>Description</th><td>{html_module.escape(f.description)}</td></tr>
                  {'<tr><th>Evidence</th><td class="evidence">' + ev_html + '</td></tr>' if f.evidence else ''}
                  {'<tr><th>Remediation</th><td class="fix">' + html_module.escape(f.remediation) + '</td></tr>' if f.remediation else ''}
                </table>
              </div>
            </div>"""

        summary_cards = "".join(
            f'<div class="scard" style="border-top:4px solid {SEVERITY_HTML[sev]}">'
            f'<div class="scard-count">{counts[sev]}</div>'
            f'<div class="scard-label">{sev}</div></div>'
            for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        )

        filter_btns = "".join(
            f'<button onclick="filterSev(\'{sev}\')" style="border-color:{SEVERITY_HTML[sev]}">{sev} ({counts[sev]})</button>'
            for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO) if counts[sev]
        )

        findings_html = "\n".join(card(i, f) for i, f in enumerate(sorted_findings, 1))

        tech_info = ""
        if self.detected_waf or self.detected_tech:
            waf_str  = ", ".join(sorted(self.detected_waf)) if self.detected_waf else "None detected"
            tech_str = ", ".join(sorted(self.detected_tech)) if self.detected_tech else "None detected"
            tech_info = f"""
            <div class="tech-row">
              <span><strong>WAF:</strong> {html_module.escape(waf_str)}</span>
              <span><strong>Technologies:</strong> {html_module.escape(tech_str)}</span>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WebScan Report — {html_module.escape(self.target)}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
    header{{background:#1e293b;padding:2rem;border-bottom:1px solid #334155}}
    header h1{{font-size:1.5rem;font-weight:700;color:#f1f5f9}}
    .meta{{margin-top:.5rem;font-size:.875rem;color:#94a3b8;display:flex;gap:1.5rem;flex-wrap:wrap}}
    .summary{{display:flex;gap:1rem;margin-top:1.5rem;flex-wrap:wrap}}
    .scard{{background:#0f172a;border-radius:8px;padding:1rem 1.5rem;min-width:110px;text-align:center}}
    .scard-count{{font-size:2rem;font-weight:700}}
    .scard-label{{font-size:.75rem;color:#94a3b8;margin-top:.25rem;letter-spacing:.05em}}
    .tech-row{{margin-top:1rem;font-size:.875rem;color:#94a3b8;display:flex;gap:2rem;flex-wrap:wrap}}
    main{{max-width:1100px;margin:2rem auto;padding:0 1rem}}
    .filters{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1.5rem}}
    .filters button{{background:transparent;color:#e2e8f0;border:1px solid;border-radius:6px;padding:.35rem .9rem;cursor:pointer;font-size:.8rem}}
    .filters button:hover{{background:#1e293b}}
    .filters button.active{{background:#1e293b}}
    .finding{{background:#1e293b;border-radius:8px;margin-bottom:.75rem;overflow:hidden}}
    .finding-header{{display:flex;justify-content:space-between;align-items:center;padding:.85rem 1.1rem;cursor:pointer;gap:1rem}}
    .finding-header:hover{{background:#263354}}
    .finding-header strong{{font-size:.9rem}}
    .cat{{font-size:.75rem;color:#94a3b8;white-space:nowrap}}
    .finding-body{{padding:1rem 1.1rem;border-top:1px solid #334155}}
    table{{width:100%;border-collapse:collapse;font-size:.875rem}}
    th{{width:130px;text-align:left;color:#94a3b8;font-weight:500;padding:.4rem .6rem .4rem 0;vertical-align:top}}
    td{{padding:.4rem 0;color:#e2e8f0;word-break:break-word}}
    td a{{color:#60a5fa;text-decoration:none}}
    td a:hover{{text-decoration:underline}}
    .evidence{{font-family:monospace;font-size:.8rem;background:#0f172a;padding:.6rem;border-radius:4px;color:#86efac;white-space:pre-wrap;word-break:break-all}}
    .fix{{color:#86efac}}
    .badge{{display:inline-block;padding:.15rem .55rem;border-radius:4px;font-size:.7rem;font-weight:700;color:#fff;letter-spacing:.04em;margin-right:.4rem}}
    .hidden{{display:none!important}}
    #searchBox{{width:100%;padding:.6rem 1rem;background:#1e293b;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:.9rem;margin-bottom:1rem}}
    #searchBox::placeholder{{color:#64748b}}
  </style>
</head>
<body>
<header>
  <h1>WebScan Security Report</h1>
  <div class="meta">
    <span>Target: <strong>{html_module.escape(self.target)}</strong></span>
    <span>Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
    <span>URLs scanned: {len(self.visited_urls)}</span>
    <span>Total findings: {len(self.findings)}</span>
    {f'<span>Proxy: {html_module.escape(self.proxy)}</span>' if self.proxy else ''}
  </div>
  {tech_info}
  <div class="summary">{summary_cards}</div>
</header>
<main>
  <input id="searchBox" type="text" placeholder="Search findings…" oninput="search(this.value)">
  <div class="filters">
    <button onclick="filterSev('ALL')" class="active">ALL</button>
    {filter_btns}
  </div>
  <div id="findings">{findings_html}</div>
  {'' if findings_html else '<p style="color:#94a3b8;text-align:center;padding:3rem">No findings to display.</p>'}
</main>
<script>
  function toggle(el){{
    var b=el.nextElementSibling;
    b.style.display=b.style.display==='none'?'block':'none';
  }}
  var currentSev='ALL';
  function filterSev(sev){{
    currentSev=sev;
    document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
    event.target.classList.add('active');
    applyFilters();
  }}
  function search(q){{applyFilters(q);}}
  function applyFilters(q){{
    q=(q||document.getElementById('searchBox').value).toLowerCase();
    document.querySelectorAll('.finding').forEach(function(el){{
      var sevOk=currentSev==='ALL'||el.dataset.sev===currentSev;
      var txt=el.textContent.toLowerCase();
      var searchOk=!q||txt.includes(q);
      el.classList.toggle('hidden',!(sevOk&&searchOk));
    }});
  }}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"{Fore.GREEN}[+] HTML report → {path}{Style.RESET_ALL}")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="webscan",
        description="WebScan v2 — Advanced Website Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webscan.py https://example.com
  python webscan.py https://example.com --crawl --depth 2
  python webscan.py https://example.com --proxy socks5://127.0.0.1:1080
  python webscan.py https://example.com --proxy http://user:pass@proxy:8080
  python webscan.py https://example.com --threads 20 --rate-limit 0.2
  python webscan.py https://example.com --output report.json --output-html report.html
  python webscan.py https://example.com --min-severity HIGH --no-ssl-verify
  python webscan.py https://example.com --verbose
  python webscan.py https://example.com --no-internal-probes --no-link-check
""",
    )
    parser.add_argument("url",
        help="Target URL (e.g. https://example.com)")
    parser.add_argument("--crawl", action="store_true",
        help="Follow internal links and scan discovered pages")
    parser.add_argument("--depth", type=int, default=1, metavar="N",
        help="Crawl depth (default: 1)")
    parser.add_argument("--threads", type=int, default=10, metavar="N",
        help="Threads for concurrent file probing (default: 10)")
    parser.add_argument("--rate-limit", type=float, default=0.0, metavar="SECS",
        help="Minimum seconds between requests (default: 0 = unlimited)")
    parser.add_argument("--timeout", type=int, default=10, metavar="SECS",
        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--proxy", metavar="URL",
        help="Proxy URL: http://host:port  |  socks5://host:port  |  http://user:pass@host:port")
    parser.add_argument("--no-ssl-verify", action="store_true",
        help="Disable SSL certificate verification")
    parser.add_argument("--user-agent", metavar="UA",
        help="Custom User-Agent string")
    parser.add_argument("--min-severity",
        choices=(CRITICAL, HIGH, MEDIUM, LOW, INFO), default=INFO,
        help="Minimum severity to display (default: INFO)")
    parser.add_argument("--output", metavar="FILE",
        help="Save JSON report to FILE")
    parser.add_argument("--output-html", metavar="FILE",
        help="Save HTML report to FILE")
    parser.add_argument("--verbose", action="store_true",
        help="Show debug output (failed requests, etc.)")
    parser.add_argument("--no-internal-probes", action="store_true",
        help="Skip dev/health/.well-known path batch (faster)")
    parser.add_argument("--no-link-check", action="store_true",
        help="Skip HEAD checks on in-page internal links")
    parser.add_argument("--link-check-max", type=int, default=15, metavar="N",
        help="Max internal links to HEAD per page (default: 15, max 40)")

    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scanner = WebScanner(
        target=url,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        crawl=args.crawl,
        depth=args.depth,
        threads=args.threads,
        rate_limit=args.rate_limit,
        proxy=args.proxy,
        user_agent=args.user_agent,
        verbose=args.verbose,
        internal_probes=not args.no_internal_probes,
        link_check=not args.no_link_check,
        link_check_max=args.link_check_max,
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted.{Style.RESET_ALL}")

    scanner.print_report(min_severity=args.min_severity)

    if args.output:
        scanner.save_json(args.output)
    if args.output_html:
        scanner.save_html(args.output_html)

    critical_count = sum(1 for f in scanner.findings if f.severity in (CRITICAL, HIGH))
    raise SystemExit(1 if critical_count else 0)


if __name__ == "__main__":
    main()
