from django.urls import path
from . import views
app_name = "Marshmallow"
urlpatterns = [ #매핑 패턴
    path('login', views.user_login),
    path('logout', views.user_logout),
    path('signup', views.signup),
    path('viewPost', views.viewPost),
    path('writePost', views.writePost),
    path('editPost', views.editPost),
    path('deletePost', views.deletePost),
    path('searchPost', views.search_posts),
    path('profile', views.profile),
    path('createpassword',views.CreatePassword),
    path('page',views.get_posts),

]