from django.urls import path

from . import views

urlpatterns = [
    path("health", views.health, name="health"),
    path("doc", views.doc, name="doc"),
    path("doc/admin", views.doc_admin, name="doc_admin"),
]
