"""Built-in wordlists and payload sets used by the pure-Python fallbacks.

These keep the platform fully functional when gobuster/ffuf are not installed.
When a system wordlist (e.g. SecLists) is present, callers may prefer it, but
these curated lists cover the high-value paths for a first-pass assessment.
"""
from __future__ import annotations

# Directory / file paths worth probing on almost any web target.
COMMON_PATHS: list[str] = [
    # admin & auth
    "admin", "administrator", "admin/login", "admin.php", "login", "login.php",
    "signin", "wp-admin", "wp-login.php", "user/login", "account", "dashboard",
    "cpanel", "manager", "console", "portal", "auth", "register", "signup",
    # api
    "api", "api/v1", "api/v2", "api/docs", "swagger", "swagger-ui.html",
    "swagger.json", "openapi.json", "graphql", "graphiql", "rest", "v1", "v2",
    # config & secrets (info disclosure)
    ".env", ".env.local", ".env.bak", "config.php", "config.json", "config.yml",
    "settings.py", "web.config", "app.config", "database.yml", "wp-config.php",
    "wp-config.php.bak", "configuration.php", "docker-compose.yml", "Dockerfile",
    # vcs
    ".git", ".git/HEAD", ".git/config", ".gitignore", ".svn", ".svn/entries",
    ".hg", ".bzr",
    # backups & archives
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "database.sql", "site.zip", "www.zip", "web.zip", "old", "bak",
    "index.php.bak", "index.html.bak", "index.bak",
    # common dirs
    "uploads", "upload", "files", "images", "img", "assets", "static", "media",
    "css", "js", "scripts", "includes", "inc", "lib", "vendor", "tmp", "temp",
    "cache", "logs", "log", "data", "download", "downloads", "docs", "doc",
    "test", "tests", "testing", "dev", "development", "staging", "demo",
    "private", "secret", "hidden", "internal",
    # info / status
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known/security.txt", "crossdomain.xml", "phpinfo.php", "info.php",
    "test.php", "status", "health", "healthz", "server-status", "server-info",
    "metrics", "actuator", "actuator/health", "actuator/env",
    # cms-ish
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php", "readme.html",
    "license.txt", "CHANGELOG.txt", "administrator/index.php",
    # misc sensitive
    ".htaccess", ".htpasswd", ".DS_Store", "composer.json", "composer.lock",
    "package.json", "yarn.lock", "Gemfile", "requirements.txt", "error_log",
    "access_log", "debug", "debug.log", "trace.axd", "elmah.axd",
]

# Endpoints/paths that, if reachable (2xx/3xx/401/403), are high-signal.
INTERESTING_MARKERS: dict[str, str] = {
    ".git": "Exposed Git repository",
    ".git/head": "Exposed Git repository",
    ".git/config": "Exposed Git repository",
    ".svn": "Exposed SVN repository",
    ".env": "Exposed environment file",
    ".env.local": "Exposed environment file",
    ".env.bak": "Exposed environment backup",
    "wp-config.php.bak": "Exposed WordPress config backup",
    "config.php": "Potential configuration file",
    "backup": "Backup resource",
    "backup.zip": "Backup archive",
    "backup.sql": "Database backup",
    "db.sql": "Database backup",
    "dump.sql": "Database backup",
    ".htpasswd": "Exposed htpasswd",
    "phpinfo.php": "PHP info disclosure",
    "info.php": "PHP info disclosure",
    "server-status": "Apache server-status exposed",
    "actuator/env": "Spring Actuator env exposed",
    ".ds_store": "Exposed .DS_Store (directory listing leak)",
    "swagger.json": "API schema exposed",
    "admin": "Admin panel",
    "administrator": "Admin panel",
    "wp-admin": "WordPress admin",
    "login": "Login portal",
    "dashboard": "Dashboard",
}

# Candidate subdomains for the built-in enumerator.
COMMON_SUBDOMAINS: list[str] = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
    "admin", "portal", "api", "api-dev", "dev", "staging", "stage", "test",
    "qa", "uat", "demo", "beta", "app", "apps", "mobile", "m", "shop", "store",
    "blog", "news", "cdn", "static", "assets", "img", "images", "media",
    "vpn", "remote", "gateway", "gw", "ns1", "ns2", "dns", "db", "sql",
    "mysql", "postgres", "redis", "cache", "git", "gitlab", "jenkins", "ci",
    "docs", "help", "support", "status", "monitor", "grafana", "kibana",
    "dashboard", "internal", "intranet", "corp", "secure", "login", "auth",
    "sso", "id", "account", "accounts", "payment", "pay", "billing",
]

# HTTP methods probed for the "insecure methods" check.
HTTP_METHODS: list[str] = [
    "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
    "HEAD",
]
