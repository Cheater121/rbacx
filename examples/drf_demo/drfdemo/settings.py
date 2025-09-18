from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "dev-example-key-not-for-prod"
DEBUG = True
ALLOWED_HOSTS = ["*"]

# Applications
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",  # needed for browsable API templates
    "django.contrib.staticfiles",
    "rest_framework",
    "docsapp",
]

# Middleware
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "drfdemo.urls"

# Templates: enable DjangoTemplates engine and app template discovery.
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],  # optional project templates folder
        "APP_DIRS": True,  # discover templates inside installed apps (incl. DRF)
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",  # required by DRF templates
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
            ],
        },
    }
]

WSGI_APPLICATION = "drfdemo.wsgi.application"

# Database: simple SQLite for demo
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static files (served by runserver in demo)
STATIC_URL = "/static/"

# DRF: keep Browsable API enabled for the demo
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    )
}
