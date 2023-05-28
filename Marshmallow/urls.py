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

    path('articles', views.ViewPost),
    path('articles/form', views.writePost),
    path('articles/<int:idx>/form', views.editPost),
    path('articles/<int:idx>/delete', views.deletePost),


    path('api/file', views.image_load),
    path('api/files/<str:uuid>', views.image_View),
    path('api/files/upload',views.image_upload),

    path('api/flag', views.flag),
] + static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)