from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
app_name = "Marshmallow"
urlpatterns = [ #매핑 패턴
    path('api/login', views.user_login),
    path('api/logout', views.user_logout),
    path('api/signup', views.signup),
    path('api/refresh-token',views.getAccessToken),
    path('api/verify',views.send_verification_email),
    path('api/reset-password/<str:token>',views.reset_password),


    path('api/articles', views.LoadPost),
    path('api/articles/form', views.writePost),
    path('api/articles/<int:idx>/form', views.editPost),
    path('api/articles/<int:idx>/delete', views.deletePost),



    path('api/file', views.image_load),
    path('api/file/upload',views.image_upload),
    path('api/file/hashtag',views.image_load_with_hashtag),
    path('api/file/<str:uuid>', views.image_view),


    path('api/flag', views.flag),
] + static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)