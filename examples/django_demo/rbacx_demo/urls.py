from django.contrib import admin
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("health", views.health, name="health"),
    path("docs", views.docs, name="docs"),
    path("admin/", admin.site.urls),
]
