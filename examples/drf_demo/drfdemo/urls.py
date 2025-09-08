
from django.urls import path
from docsapp.views import DocsView
urlpatterns = [ path('docs', DocsView.as_view()) ]
