"""Settings for the async Django + RBACX demo.

Run with uvicorn (ASGI):
    uvicorn async_rbacx_demo.asgi:application --port 8005 --reload

Test:
    curl http://127.0.0.1:8005/health
    curl http://127.0.0.1:8005/doc
    curl -H "X-Role: admin" http://127.0.0.1:8005/doc
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "async-demo-secret-key-not-for-production"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "async_rbacx_demo",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    # Inject trace/request-id into logging context (async-safe):
    "rbacx.adapters.django.trace.AsyncTraceIdMiddleware",
    # Demo: read X-Role header and attach a fake user to the request:
    "async_rbacx_demo.middleware.XRoleDemoMiddleware",
    # Attach RBACX guard to each request (async-safe):
    "rbacx.adapters.django.middleware.AsyncRbacxDjangoMiddleware",
]

ROOT_URLCONF = "async_rbacx_demo.urls"
ASGI_APPLICATION = "async_rbacx_demo.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True

# RBACX: tell AsyncRbacxDjangoMiddleware how to build the guard
RBACX_GUARD_FACTORY = "async_rbacx_demo.rbacx_factory.build_guard"
