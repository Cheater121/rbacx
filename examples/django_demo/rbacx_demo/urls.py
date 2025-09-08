
from django.urls import path
from .views import index
from .views import health
urlpatterns = [path("", index), path("health", health)]
