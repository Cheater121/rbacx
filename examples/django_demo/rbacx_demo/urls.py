from django.contrib import admin
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("health", views.health, name="health"),
    path("doc", views.doc, name="doc"),
    path("admin/", admin.site.urls),
]
