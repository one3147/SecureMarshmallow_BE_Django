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

def default(request): #Defualt
    return HttpResponse("Root Page")


def index(request): #기본 페이지
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

def user_logout(request): #로그아웃
    if request.user.is_authenticated: #세션 파기
        if request.COOKIES.get('sessionid'):
            logout(request)
        response = JsonResponse({"success": True})
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response
    else:
        return JsonResponse({'success': False})

def signup(request): #회원가입
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

def writePost(request, idx): #글 작성
    if request.method == 'POST':
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
        if password:
            board = Board(idx=idx, title=title, contents=contents, password=password)
        else:
            board = Board(idx=idx, title=title, contents=contents)
        board.save()
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def viewPost(request): #글 조회
    if request.method == 'GET':
        idx = request.POST.get('idx')
        try:
            post = Board.objects.get(idx=idx)
            return JsonResponse({'success': 'True', 'post': f'{post}', 'title' : f'{post.title}', 'contents' : f'{post.contents}','password': f'{post.password}'})
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def editPost(request): #글 수정
    if request.method == 'PUT' or request.method == 'PATCH':
        idx = request.PUT.get('idx')
        if not idx:
            idx = request.PATCH.get('idx')
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
    else:
        return JsonResponse({'error': "Invalid Request Method"})

def deletePost(request): #글 삭제
    if request.method == 'DELETE':
        idx = request.POST.get('idx')
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

def search_posts(request): #글 검색
    if request.method == 'GET':
        search_word = request.POST.get('search_word')
        posts = Board.search_posts(search_word)
        return JsonResponse({'result': f'{posts}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def CreatePassword(request): #비밀번호 생성
    if request.method == 'POST':
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(8))
        return JsonResponse({'Password' : f"{password}"})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def get_posts(request): #페이징
    if request.method == 'GET':
        number = request.POST.get('number')
        paginator = Paginator(Board.objects.all(), 10)
        page_number = request.POST.get('page', number)
        page_obj = paginator.get_page(page_number)
        posts = page_obj.object_list
        response_data = {
            'count': paginator.count,
            'num_pages': paginator.num_pages,
            'posts': [{'title': post.title, 'contents': post.contents} for post in posts],
        }
        return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Invalid request method'})

def profile(request): #유저 프로필
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
