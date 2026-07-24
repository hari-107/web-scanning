"""Django settings for the Web Security Assessment Platform."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Security / core ---------------------------------------------------------
# For a local assessment tool this key is fine as-is; override via env in prod.
SECRET_KEY = os.environ.get(
    "WEBSEC_SECRET_KEY",
    "dev-insecure-key-change-me-0123456789abcdefghijklmnopqrstuvwxyz",
)
DEBUG = os.environ.get("WEBSEC_DEBUG", "1") == "1"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "scanner",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "websec.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "websec.wsgi.application"

# --- Database ----------------------------------------------------------------
# Defaults target a stock XAMPP/MariaDB install (user "root", empty password).
# Override any of these via environment variables without editing this file.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("WEBSEC_DB_NAME", "websec"),
        "USER": os.environ.get("WEBSEC_DB_USER", "root"),
        "PASSWORD": os.environ.get("WEBSEC_DB_PASSWORD", ""),
        "HOST": os.environ.get("WEBSEC_DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("WEBSEC_DB_PORT", "3306"),
        "OPTIONS": {
            "charset": "utf8mb4",
        },
    }
}

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "scanner" / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Scanner configuration ---------------------------------------------------
SCAN_SETTINGS = {
    "MAX_CRAWL_PAGES": int(os.environ.get("WEBSEC_MAX_CRAWL_PAGES", "80")),
    "MAX_CRAWL_DEPTH": int(os.environ.get("WEBSEC_MAX_CRAWL_DEPTH", "3")),
    "REQUEST_TIMEOUT": int(os.environ.get("WEBSEC_REQUEST_TIMEOUT", "12")),
    "HTTP_THREADS": int(os.environ.get("WEBSEC_HTTP_THREADS", "16")),
    "PORT_SCAN_THREADS": int(os.environ.get("WEBSEC_PORT_THREADS", "200")),
    "USER_AGENT": os.environ.get(
        "WEBSEC_USER_AGENT",
        "WebSecScanner/1.0 (+authorized-assessment)",
    ),
    # Directory-enum wordlist size cap for the built-in fallback.
    "DIR_WORDLIST_LIMIT": int(os.environ.get("WEBSEC_DIR_WORDLIST_LIMIT", "600")),
}
