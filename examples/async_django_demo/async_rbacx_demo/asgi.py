"""ASGI entry point for the async RBACX demo."""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "async_rbacx_demo.settings")

application = get_asgi_application()
