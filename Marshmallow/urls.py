from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
app_name = "Marshmallow"
urlpatterns = [ #매핑 패턴
    path('', views.default),
    path('error', views.index),
    path('api/login', views.user_login),
    path('api/logout', views.user_logout),
    path('api/sign-up', views.signup),
    path('api/articles', views.writePost),
    path('api/articles/<int:idx>', views.Post),
    path('api/articles/<int:idx>', views.Post),
    path('api/articles/<int:idx>', views.Post),
    path('article/search', views.search_posts),
    path('api/profile', views.profile),
    path('createpassword',views.CreatePassword),
    path('api/articles',views.get_posts),
    path('getAccessToken',views.getAccessToken)
] + static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)