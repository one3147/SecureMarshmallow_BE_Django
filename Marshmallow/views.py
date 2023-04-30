from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import *
from django.http import JsonResponse
from Marshmallow.models import Marshmallow_User,Board
from rest_framework_simplejwt.tokens import RefreshToken
import secrets
import string
from rest_framework_simplejwt.views import TokenRefreshView
from django.core.paginator import Paginator
from Marshmallow.models import Marshmallow_User

def default(request):
    return HttpResponse("api")

def index(request):
    return HttpResponse("200 OK")

def login(request):
    if request.method == 'POST':
        id = request.POST.get('id')
        password = request.POST.get('password')
        user = Marshmallow_User.objects.create_user('username', 'email', 'password')
        user = authenticate(request, id=id, password=password)
        if user is not None:
            #login(request, user)
            # 토큰 발급
            #refresh = RefreshToken.for_user(user)
            return JsonResponse({
                #'refresh': str(refresh),
                #'access': str(refresh.access_token),
                'success': 'ok'
            })
        else:
            return JsonResponse({'success': f'{id} {password}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def logout(request):
    if request.user.is_authenticated:
        logout(request)
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'success': False})