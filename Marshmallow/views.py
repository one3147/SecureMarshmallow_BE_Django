from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import *
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import base64
from Marshmallow.models import Marshmallow_User, Board, image
import secrets
import string
from django.core.paginator import Paginator
from .models import Marshmallow_User
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
import os
from datetime import timedelta
import re
import bcrypt
def default(request):
    return HttpResponse("Root Page")


def index(request):
    return HttpResponse("Main")


def user_login(request):
    if request.method == 'GET':
        id = request.GET.get('id')
        password = request.GET.get('password')
        if len(id) > 50 or len(password) > 150:
            return JsonResponse({'error': 'id or Password is too Long.'})
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist as e:
            return JsonResponse({'error': str(e)})
        stored_password = user.password
        input_password = password.encode('utf-8')
        if bcrypt.checkpw(input_password, stored_password.encode('utf-8')):
            login(request, user)
            refresh_token = RefreshToken.for_user(user)
            access_token = refresh_token.access_token

            refresh_token.set_exp(lifetime=timedelta(days=1))
            access_token.set_exp(lifetime=timedelta(hours=1))

            response = JsonResponse({
                "user": user.id,
                "message": "login success",
                "access_token": str(access_token),
                "refresh_token": str(refresh_token),
            })

            response.set_cookie('access_token', str(access_token))
            response.set_cookie('refresh_token', str(refresh_token))
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
        return JsonResponse({'success': 'You are not logged in.'})


def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if not re.search(r'\d', password):
            return JsonResponse({'error' : 'Password must contains Number.'})
        if not re.search(r'[a-zA-Z]', password):
            return JsonResponse({'error' : 'Password must contains Alphabet.'})
        if not re.search(r"[!@#$%^&*()\-=_+[\]{};':\"|,.<>/?]+", password):
            return JsonResponse({'error' : 'Password must contains special symbol.'})
        if len(password) < 10:
            return JsonResponse({'error' : 'Password must be more than 10 digits.'})
        if len(password) > 150:
            return JsonResponse({'error' : 'Password must be less than 150 digits.'})

        id = request.POST.get('id')
        email = request.POST.get('email')
        try:
            Marshmallow_User.objects.get(id=id)
            return JsonResponse({'error': 'id is already exists.'})
        except Marshmallow_User.DoesNotExist:
            pass

        try:
            Marshmallow_User.objects.get(email=email)
            return JsonResponse({'error': 'Email is already exists.'})
        except Marshmallow_User.DoesNotExist:
            pass
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if len(username) > 100:
            return JsonResponse({'error': 'Username must be less than 100 digits.'})
        if len(email) > 320:
            return JsonResponse({'error': 'Email must be less than 320 digits.'})
        salt = bcrypt.gensalt()
        new_password = password.encode('utf-8')
        hash_password = bcrypt.hashpw(new_password, salt)
        decode_hash_password = hash_password.decode('utf-8')
        user = Marshmallow_User(name=username, password=decode_hash_password, email=email, id=id)
        user.save()
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def writeOrViewPost(request):
    if request.method == 'POST': # 게시글 작성
        idx = request.POST.get('idx')
        id = request.POST.get('id')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
        if password:
            board = Board(idx=idx, title=title, contents=contents, password=password, id=id)
        else:
            board = Board(idx=idx, title=title, contents=contents, id=id)
        board.save()
        return JsonResponse({'success': True})
    elif request.method == 'GET': # 게시글 페이징 , 게시글 다수 조회
        id = request.GET.get('id')
        paginator = Paginator(Board.objects.filter(id=id), 10)
        page_number = request.GET.get('number')
        if not page_number:
            page_number = 1
        page_obj = paginator.get_page(page_number)
        posts = page_obj.object_list
        if not posts:
            return JsonResponse({'error': 'error'})
        response_data = {
            'count': len(posts),
            'num_pages': page_number,
            'posts': [{'idx': post.idx, 'title': post.title, 'contents': post.contents} for post in posts],
        }
        return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Invalid request method'})


def Post(request, idx):
    if request.method == 'GET': # 게시글 단일 조회
        id = request.GET.get('id')
        try:
            post = Board.objects.get(idx=idx, id=id)
            return JsonResponse({'success': 'True', 'idx': f'{idx}', 'post': f'{post}', 'title': f'{post.title}',
                                 'contents': f'{post.contents}', 'password': f'{post.password}'})
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    elif request.method in ['POST'] and not request.POST.get('delete'):  # 게시글 수정
        id = request.POST.get('id')
        if not id:
            return JsonResponse({'error': 'with id'})
        try:
            board = Board.objects.get(idx=idx, id=id)
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist.'})
        title = request.POST.get('title') or board.title
        contents = request.POST.get('contents') or board.contents
        password = request.POST.get('password') or board.password
        if password:
            board.title = title
            board.contents = contents
            board.password = password
        else:
            board.title = title
            board.contents = contents
        board.save()
        return JsonResponse({'success': True})
    elif request.method == 'POST' and request.POST.get('delete'):  # 게시글 삭제
        id = request.POST.get('id')
        password = request.POST.get('password')
        board = Board.objects.get(idx=idx, id=id)
        if board is None:
            return JsonResponse({'error': 'Post does not exist.'})
        elif board.password != password:
            return JsonResponse({'error': 'Wrong password.'})
        else:
            board.delete_board()
            return JsonResponse({'Delete': True})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def search_posts(request):
    if request.method == 'GET':
        id = request.GET.get('id')
        search_word = request.GET.get('search_word')
        posts = Board.search_posts(search_word, id)
        return JsonResponse({'result': f'{posts}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def CreatePassword(request):
    if request.method == 'POST':
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        return JsonResponse({'Password': f"{password}"})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def profile(request):
    if request.method == 'POST':
        id = request.POST.get('id')
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist as e:
            return JsonResponse({'error': f'{str(e)}'})
        return JsonResponse({'user': f'{user}'})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def getAccessToken(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if refresh_token:
        token = RefreshToken(refresh_token)
        access_token = str(token.access_token)
        response = JsonResponse({'access_token': access_token})
        response.set_cookie('access_token', access_token)
        return response
    else:
        return JsonResponse({'error': "You don't Have RefreshToken."})


def image_View(request):
    if request.method == 'POST':
        id = request.POST.get('id')
        filename = request.POST.get('filename')
        file_path = f'./media/images/{filename}'
        try:
            imageModel = image.objects.get(image=filename, id=id)
        except image.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
        with open(file_path, 'rb') as image_file:
            image_data = image_file.read()
        image_data_base64 = base64.b64encode(image_data).decode('utf-8')
        return JsonResponse({'image_data': image_data_base64})
    else:
        return JsonResponse({'error' : 'Invalid Request Method'})

def image_upload(request):
    if request.method == 'POST':
        Realimage = request.FILES.get('image', None)
        id = request.POST.get('id')
        if Realimage:
            try:
                save_path = './media/images/'
                file_name = Realimage.name
                file_path = os.path.join(save_path, file_name)
                imageModel = image(id=id,image=file_name)
                imageModel.save()
                with open(file_path, 'wb+') as destination:
                    for chunk in Realimage.chunks():
                        destination.write(chunk)
                return JsonResponse({'success': True, 'file_path': file_path})
            except Exception as e:
                return JsonResponse({'error': str(e)})
        else:
            return JsonResponse({'error': 'No Image..'})
    else:
        return JsonResponse({'error' : 'Invalid Request Method'})


def delete_uploaded_image(request):
    if request.method == 'POST':
        filename = request.POST.get('filename')
        id = request.POST.get('id')
        imageModel = image.objects.get(id=id)
        file_path = f'./media/images/{filename}'
        if file_path:
            deleted = delete_image(file_path)
            if deleted:
                imageModel.delete_image()
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'error': 'File not found'})
        else:
            return JsonResponse({'error': 'Invalid file path'})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def delete_image(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        else:
            return False
    except Exception as e:
        return str(e)

def flag(request):
    if request.method == 'PUT':
        return HttpResponse("Marshmallow{E3sT3R_3gg!}")
    else:
        return JsonResponse({'Status code': '404'})
