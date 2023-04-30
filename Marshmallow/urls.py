from django.urls import path
from . import views
app_name = "Marshmallow"
urlpatterns = [
    path('', views.index),
    path('login/', views.login),
]