from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
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
    path('getAccessToken',views.getAccessToken)
] + static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)