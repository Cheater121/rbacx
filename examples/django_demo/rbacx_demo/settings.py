
from __future__ import annotations
import os, logging.config
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_KEY = "rbacx-demo-secret-key"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "rbacx.adapters.django.trace.TraceIdMiddleware",
    "rbacx.adapters.django.middleware.RbacxDjangoMiddleware",
]

ROOT_URLCONF = "rbacx_demo.urls"
TEMPLATES = []
WSGI_APPLICATION = "rbacx_demo.wsgi.application"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.path.join(BASE_DIR, "db.sqlite3")}}

LOGGING = {
  "version": 1,
  "disable_existing_loggers": False,
  "formatters": {"simple": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
  "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "simple", "filters": ["trace"]}},
  "filters": {"trace": {"()": "rbacx.logging.context.TraceIdFilter"}},
  "root": {"level": "INFO", "handlers": ["console"]},
}

RBACX_GUARD_FACTORY = "rbacx_demo.rbacx_factory.build_guard"

# Optional JSON logging
if os.getenv("RBACX_LOG_JSON") == "1":
    LOGGING["formatters"]["simple"] = {
        "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
        "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s"
    }
