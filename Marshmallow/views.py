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

def default(request): #Defualt
    return HttpResponse("api")


def index(request): #기본 페이지
    return HttpResponse("200 OK")

def login(request): #로그인
    if request.method == 'POST':
        id = request.POST.get('id')
        password = request.POST.get('password')
        user = Marshmallow_User.objects.create_user('username', 'email', 'password')
        user = authenticate(request, id=id, password=password)
        if user is not None:
            login(request, user) #로그인 처리
            refresh = RefreshToken.for_user(user) #토큰 발급
            return JsonResponse({ #반환
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'success': 'ok'
            })
        else:
            return JsonResponse({'success': f'{id} {password}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def logout(request): #로그아웃
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
        user = Marshmallow_User.objects.create_user(Name=username, Password=password, email=email, id=id)
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
            board = Board.objects.create_board(idx=idx,title=title,contents=contents,password=password)
        else:
            board = Board.objects.create_board(idx=idx,title=title,contents=contents)
        board.save()
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def viewPost(request): #글 조회
    if request.method == 'GET':
        idx = request.GET.get('idx')
        try:
            post = Board.objects.get(idx=idx)
            return post
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def editPost(request, pk): #글 수정
    board = get_object_or_404(Board, pk=pk)
    if request.method == 'POST':
        idx = request.POST.get('idx')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
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
        board = Board.get_board(idx)
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
    if request.method == 'GET':
        search_word = request.GET.get('search_word')
        posts = Board.search_posts(search_word)
        return JsonResponse({'result': f'{posts}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def CreatePassword(request): #비밀번호 생성
    if request.method == 'GET':
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(8))
        return JsonResponse({'Password' : f"{password}"})
    else:
        return JsonResponse({'error': 'Invalid request method'})

def get_posts(request): #페이징
    if request.method == 'GET':
        paginator = Paginator(Board.objects.all(), 10)
        page_number = request.GET.get('page', 1)
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
    user_id = request.GET.get('id')
    user = get_object_or_404(Marshmallow_User, id=id)
    if request.method == 'GET':
        return user
    else:
        return JsonResponse({'error' : 'Invalid request method'})



class RefreshTokenView(TokenRefreshView): #토큰 클래스
    pass
