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
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from .models import Marshmallow_User


def default(request): #Defualt
    return HttpResponse("api")


def index(request): #기본 페이지
    return HttpResponse("200 OK")


def user_login(request):
    if request.method == 'POST':
        id = request.POST.get('id')
        password = request.POST.get('password')
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist:
            return JsonResponse({'success': 'fail to get user info'})

        if password == user.password:
            login(request, user)
            response = JsonResponse({'success': f'{request.user}'})
            return response
        else:
            return JsonResponse({'success': 'fail to login'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def user_logout(request): #로그아웃
    if request.user.is_authenticated: #세션 파기
        logout(request)
        return JsonResponse({'success': True})
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

def writePost(request): #글 작성
    if request.method == 'POST':
        idx = request.POST.get('idx')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
        if password:
            board = Board(idx=idx,title=title,contents=contents,password=password)
        else:
            board = Board(idx=idx,title=title,contents=contents)
        board.save()
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def viewPost(request): #글 조회
    if request.method == 'POST':
        idx = request.POST.get('idx')
        try:
            post = Board.objects.get(idx=idx)
            return JsonResponse({'success': 'True', 'post': f'{post}'})
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def editPost(request): #글 수정
    if request.method == 'POST':
        idx = request.POST.get('idx')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
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
        return JsonResponse({'error': "error"})

def deletePost(request): #글 삭제
    if request.method == 'POST':
        idx = request.POST.get('idx')
        password = request.POST.get('password')
        board = Board.objects.get(idx=idx)
        if board is None:
            return JsonResponse({'error': 'Post does not exist.'})
        elif board.password != password:
            return JsonResponse({'error': 'Wrong password.'})
        else:
            board.delete_board()
            return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def search_posts(request): #글 검색
    if request.method == 'POST':
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
    if request.method == 'POST':
        paginator = Paginator(Board.objects.all(), 10)
        page_number = request.POST.get('page', 1)
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
    if request.method == 'POST':
        id = request.POST.get('id')
        user = get_object_or_404(Marshmallow_User, id=id)
        return JsonResponse({'user': f'{user}'})
    else:
        return JsonResponse({'error' : 'Invalid request method'})



class RefreshTokenView(TokenRefreshView): #토큰 클래스
    pass
