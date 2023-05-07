from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import *
from django.http import JsonResponse
from Marshmallow.models import Marshmallow_User,Board
import secrets
import string
from django.core.paginator import Paginator
from .models import Marshmallow_User
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
import os

def default(request):
    return HttpResponse("Root Page")


def index(request):
    return HttpResponse("Main")


def user_login(request):
    if request.method == 'GET':
        id = request.GET.get('id')
        password = request.GET.get('password')
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist as e:
            return JsonResponse({'error': f'{str(e)}'})
        if password == user.password:
            login(request,user)
            token = RefreshToken.for_user(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            response = JsonResponse({
                "user": user.id,
                "message": "login success",
                "access_token": access_token,
                "refresh_token": refresh_token,
            })
            response.set_cookie('access_token', access_token)
            response.set_cookie('refresh_token', refresh_token)
            return response
        else:
            return JsonResponse({'success': 'fail to login'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def user_logout(request):
    if request.user.is_authenticated:
        if request.COOKIES.get('sessionid'):
            logout(request)
        response = JsonResponse({"success": True})
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response
    else:
        return JsonResponse({'success': False})

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        id = request.POST.get('id')
        email = request.POST.get('email')
        user = Marshmallow_User(name=username, password=password, email=email, id=id)
        user.save()
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def writeOrViewPost(request):
    if request.method == 'POST':
        idx = request.POST.get('idx')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
        if password:
            board = Board(idx=idx, title=title, contents=contents, password=password)
        else:
            board = Board(idx=idx, title=title, contents=contents)
        board.save()
        return JsonResponse({'success': True})
    elif request.method == 'GET':
        paginator = Paginator(Board.objects.all(), 10)
        page_number = 1
        page_number = request.GET.get('number')
        page_obj = paginator.get_page(page_number)
        posts = page_obj.object_list
        response_data = {
            'count': len(posts),
            'num_pages': page_number,
            'posts': [{'idx' : post.idx, 'title': post.title, 'contents': post.contents} for post in posts],
        }
        return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Invalid request method'})

def Post(request,idx):
    if request.method == 'GET':
        try:
            post = Board.objects.get(idx=idx)
            return JsonResponse({'success': 'True', 'post': f'{post}', 'title' : f'{post.title}', 'contents' : f'{post.contents}','password': f'{post.password}'})
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    elif request.method == 'PUT' or request.method == 'PATCH':
            title = request.PUT.get('title')
            if not title:
                title = request.PATCH.get('title')
            contents = request.PUT.get('contents')
            if not contents:
                contents = request.PATCH.get('contents')
            password = request.PUT.get('password')
            if not password:
                password = request.PATCH.get('password')
            board = Board.objects.get(idx=idx)
            if password:
                board.idx = idx
                board.title = title
                board.contents = contents
                board.password = password
            else:
                board.idx = idx
                board.title = title
                board.contents = contents
            board.save()
            return JsonResponse({'success': True})
    elif request.method == 'DELETE':
        password = request.POST.get('password')
        board = Board.objects.get(idx=idx)
        if board is None:
            return JsonResponse({'error': 'Post does not exist.'})
        elif board.password != password:
            return JsonResponse({'error': 'Wrong password.'})
        else:
            if board.image:
                os.system(f"rm -rf ./media/{board.image}")
            board.delete_board()
            return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def search_posts(request):
    if request.method == 'GET':
        search_word = request.POST.get('search_word')
        posts = Board.search_posts(search_word)
        return JsonResponse({'result': f'{posts}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def CreatePassword(request):
    if request.method == 'POST':
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(8))
        return JsonResponse({'Password' : f"{password}"})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def profile(request):
    if request.method == 'GET':
        id = request.POST.get('id')
        user = get_object_or_404(Marshmallow_User, id=id)
        return JsonResponse({'user': f'{user}'})
    else:
        return JsonResponse({'error' : 'Invalid request method'})


def getAccessToken(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if refresh_token:
        token = RefreshToken(refresh_token)
        access_token = str(token.access_token)
        response = JsonResponse({'access_token': access_token})
        response.set_cookie('access_token', access_token, httponly=True)
        return response
    else:
        return JsonResponse({'error':'error'})

def image_upload(request):
    image = request.FILES.get('image', None)
    if image:
        print(1)
    else:
        return JsonResponse({'error': 'No Image..'})
