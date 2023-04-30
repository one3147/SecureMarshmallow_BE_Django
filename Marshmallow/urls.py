from django.urls import path
from . import views
app_name = "Marshmallow"
urlpatterns = [
    path('', views.index),
    path('login/', views.login),
    path('logout/', views.logout),
    path('signup/', views.signup),
    path('viewPost/<int:pk>/', views.viewPost),
    path('writePost/', views.writePost),
    path('editPost/<int:pk>/', views.editPost),
    path('deletePost/', views.deletePost),

]