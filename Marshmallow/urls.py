from django.urls import path
from . import views
app_name = "Marshmallow"
urlpatterns = [
    path('login/', views.login),
    path('logout/', views.logout),
    path('signup/', views.signup),
    path('viewPost/<int:pk>/', views.viewPost),
    path('writePost/', views.writePost),
    path('editPost/<int:pk>/', views.editPost),
    path('deletePost/', views.deletePost),
    path('searchPost/', views.search_posts),
    path('profile/', views.profile),
    path('createpassword/',views.CreatePassword),

]