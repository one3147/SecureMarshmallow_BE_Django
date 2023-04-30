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
