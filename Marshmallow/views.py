import jwt
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

import config
from Marshmallow.models import article
from django.core.paginator import Paginator
from config import settings
from .models import Marshmallow_User
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken
import os
import re
import bcrypt
from datetime import timedelta
from django.http import JsonResponse
import uuid
import datetime
from .models import image,imageData
secret_key = config.settings.SECRET_KEY

def user_login(request):
    if request.method == 'GET':
        id = request.GET.get('id')
        password = request.GET.get('password')
        try:
            if len(id) > 50 or len(password) > 255:
                raise ValueError('ID or Password is too Long.')
        except ValueError as e:
            return JsonResponse({'error': str(e)})
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist as e:
            return JsonResponse({'error': str(e)})
        stored_password = user.password.encode('utf-8')
        input_password = password.encode('utf-8')
        if bcrypt.checkpw(input_password, stored_password):
            refresh_token = RefreshToken.for_user(user)
            access_token = refresh_token.access_token
            refresh_token.set_exp(lifetime=timedelta(days=1))
            access_token.set_exp(lifetime=timedelta(hours=1))
            refresh_token_encoded = jwt.encode(refresh_token.payload, secret_key, algorithm='HS256')
            access_token_encoded = jwt.encode(access_token.payload, secret_key, algorithm='HS256')

            response = JsonResponse({
                "user": user.id,
                "success": True,
                "access_token": access_token_encoded,
                "refresh_token": refresh_token_encoded,
            })
            return response
        else:
            return JsonResponse({'success': False})

def user_logout(request):
    if request.method == 'POST':
        response = JsonResponse({"success": True})
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

    else:
        return JsonResponse({'error': 'Invalid request Method.', 'success': False})


def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        id = request.POST.get('id')
        email = request.POST.get('email')
        try:
            if len(password) > 255:
                raise ValueError('Password must be less than 255 digits.')
            if len(password) < 10:
                raise ValueError('Password must be more than 10 digits.')
            if len(id) > 50:
                raise ValueError('ID must be less than 50 digits.')
            if len(username) > 100:
                raise ValueError('Username must be less than 100 digits.')
            if len(email) > 320:
                raise ValueError('Email must be less than 320 digits.')
        except ValueError as e:
            return JsonResponse({'error': str(e)})
        try:
            if not re.search(r'\d', password):
                raise Exception('Password must contain a number.')
            if not re.search(r'[a-zA-Z]', password):
                raise Exception('Password must contain an alphabet.')
            if not re.search(r"[!@#$%^&*()\-=_+[\]{};':\"|,.<>/?]+", password):
                raise Exception('Password must contain a special symbol.')
        except Exception as e:
            return JsonResponse({'error': str(e)})
        try:
            Marshmallow_User.objects.get(id=id)
            return JsonResponse({'error': 'id is already exists.', 'success': False})
        except Marshmallow_User.DoesNotExist:
            pass
        try:
            Marshmallow_User.objects.get(email=email)
            return JsonResponse({'error': 'Email is already exists.', 'success': False})
        except Marshmallow_User.DoesNotExist:
            pass
        salt = bcrypt.gensalt()
        new_password = password.encode('utf-8')
        hash_password = bcrypt.hashpw(new_password, salt)
        decode_hash_password = hash_password.decode('utf-8')
        user = Marshmallow_User(name=username, password=decode_hash_password, email=email, id=id)
        user.save()
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False})

def getAccessToken(request):
    if request.method == 'POST':
        refresh_token = request.POST.get('refresh_token')
        try:
            if len(refresh_token) > 100:
                raise ValueError("Refresh Token's length is too long.")
        except ValueError as e:
            return JsonResponse({'error': str(e)})
        if refresh_token:
            access_token = refresh_token.access_token
            access_token.set_exp(lifetime=timedelta(hours=1))
            access_token_encoded = jwt.encode(access_token.payload, secret_key, algorithm='HS256')
            response = JsonResponse({'access_token': access_token_encoded})
            return response
        else:
            return JsonResponse({'error': "You don't Have RefreshToken.", 'success': False})
    else:
        return JsonResponse({'error': 'Invalid request method.', 'success': False})








    # 메모 CRUD









def writePost(request):
    access_token = request.POST.get('access_token') or request.GET.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need an Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
        MarshmallowUser = Marshmallow_User.objects.get(id=user_id)
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}', 'success': False})
    if request.method == 'POST':  # 게시글 작성
        idx = request.POST.get('idx')
        content = request.POST.get('content')
        hashtag = request.POST.get('hashtag')
        title = request.POST.get('title')
        if checkLength(user_id, 50) or checkLength(title, 255) or checkLength(content, 10000) or checkLength(hashtag,255):
            return JsonResponse({'error': False})

        if all(var is None for var in [title, content, user_id, hashtag]):
            return JsonResponse({'error': False})
        board = article(id=idx,title=title, content=content, created_by=user_id,hashtag=hashtag,created_at=timezone.now())
        board.save()
        return JsonResponse({'success': True})


def LoadPost(request):
    access_token = request.POST.get('access_token') or request.GET.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need an Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
        MarshmallowUser = Marshmallow_User.objects.get(id=user_id)
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}', 'success': False})
    if request.method == 'GET':  # 게시글 페이징 , 게시글 다수 조회
        searchValue = request.GET.get('searchValue')
        searchType = request.GET.get('searchType')
        if searchValue and searchType:
            if any(checkLength(var, 50) for var in [user_id, searchValue, searchType]):
                return JsonResponse({'success': False})
            return search_posts(searchValue, searchType, user_id)
        if searchValue and not searchType:
            if any(checkLength(var, 50) for var in [user_id, searchValue]):
                return JsonResponse({'success': False})
            return search_posts(searchValue, searchType, user_id)
        else:
            paginator = Paginator(article.objects.filter(created_by=user_id), 10)
            page_number = int(request.GET.get('number'))
            if not page_number:
                page_number = 1
            if page_number > 99999:
                return JsonResponse({'error': False})
            page_obj = paginator.get_page(page_number)
            posts = page_obj.object_list
            if not posts:
                return JsonResponse({'error': 'No posts', 'success': False, 'user': f'{user_id}'})
            response_data = {
                'count': len(posts),
                'num_pages': page_number,
                'posts': [{'idx': post.id, 'title': post.title,'content':post.content, 'id': post.id} for post in posts],
            }
            return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False})

def search_posts(searchValue,searchType,userId):
    if searchType == 'TITLE':
        articles = article.objects.filter(title__contains=searchValue,created_by=userId)
    elif searchType == 'ID':
        articles = article.objects.filter(id=searchValue,created_by=userId)
    elif searchType == 'CONTENT':
        articles = article.objects.filter(content__contains=searchValue,created_by=userId)
    return JsonResponse({'result': f'{articles}'})




def editPost(request, idx):
    access_token = request.GET.get('access_token') or request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':  # 게시글 수정
        if checkLength(id, 50):
            return JsonResponse({'success': False})
        try:
            board = article.objects.get(id=idx, created_by=id)
        except article.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist.', 'success': False})
        title = request.POST.get('title') or board.title
        contents = request.POST.get('contents') or board.content
        hashtag = request.POST.get('hashtag') or board.hashtag
        if checkLength(title, 255) or checkLength(contents, 3000) or checkLength(hashtag,255):
            return JsonResponse({'success': False})
        board.modified_at = timezone.now()
        board.title = title
        board.hashtag = hashtag
        board.content = contents
        board.save()
        return JsonResponse({'success': True})


def deletePost(request, idx):
    access_token = request.GET.get('access_token') or request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':  # 게시글 삭제
        if idx > 99999 or checkLength(id, 50):
            return JsonResponse({'success': False})

        board = article.objects.get(id=idx,created_by=id)
        if board is None:
            return JsonResponse({'error': 'Post does not exist.', 'success': False})
        else:
            board.delete_board()
            return JsonResponse({'Delete': True})
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False})



def viewPost(request,idx):
    access_token = request.GET.get('access_token') or request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':  # 게시글 단일 조회
        if idx > 99999 or checkLength(idx, 50):
            return JsonResponse({'success': False})
        try:
            post = article.objects.get(id=idx, created_by=user_id)
            return JsonResponse({'success': 'True', 'idx': f'{idx}', 'post': f'{post}', 'title': f'{post.title}',
                                 'contents': f'{post.contents}', 'password': f'{post.password}'})
        except article.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    else:
        return JsonResponse({'error': 'Invalid request method.'})







    # 파일 CRUD







def filename_filter(filename):
    pattern = r'^[\w\s\'-가-힣]+$'
    return re.match(pattern, filename) is not None


def image_View(request, uuid):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':
        try:
            if len(id) > 50:
                raise ValueError("id must be less than 50 digits.")
            if len(uuid) > 255:
                raise ValueError("uuid must be less than 255 digits.")
        except ValueError as e:
            return JsonResponse({'error': str(e)})
        try:
            image_obj = imageData.objects.get(id=uuid)
        except image.DoesNotExist:
            return JsonResponse({'error': 'Image does not exist', 'success': False})

        return image_obj
    elif request.method=='DELETE':
       delete_uploaded_image(uuid,id)
    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False})
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp','.heic']

def image_load(request):
    if request.method=='GET':
        access_token = request.POST.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'You need an Access Token', 'success': False})
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            created_by = decoded_token.get('user_id')
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}'})

        try:
            if len(created_by) > 50:
                raise ValueError("id must be less than 50 digits.")
        except ValueError as e:
            return JsonResponse({'error': str(e)})

        image_list = image.objects.get()
        response = ""
        for i in image_list:
            response += i
        return JsonResponse({'image_list': response})
    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False})


def image_upload(request):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need an Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        created_by = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':
        Realimage = request.FILES.get('image', None)
        try:
            if len(created_by) > 50:
                raise ValueError("id must be less than 50 digits.")

            if not Realimage:
                return JsonResponse({'error': 'No Image.', 'success': False})

            file_extension = os.path.splitext(Realimage.name)[1].lower()
            if file_extension not in ALLOWED_EXTENSIONS:
                return JsonResponse({'error': 'Invalid file extension.', 'success': False})

            file_size = Realimage.size
            max_file_size = 8 * 1024 * 1024
            if file_size > max_file_size:
                return JsonResponse({'error': 'File Maximum size is 8MB.', 'success': False})

            file_name = Realimage.name
            file_data = Realimage.read()
            UUID = uuid.uuid4()
            file_entity = image(
                id=UUID,
                file_name=file_name,
                file_size=file_size,
                created_at=datetime.datetime.now(),
                is_deleted=False,
                created_by=created_by
            )
            file_entity.save()
            file_data_entity = imageData(
                id=UUID,
                data=file_data
            )
            file_data_entity.save()
            return JsonResponse({'success': True})

        except ValueError as e:
            return JsonResponse({'error': str(e)})

        except Exception as e:
            return JsonResponse({'error': str(e)})

    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False})


def delete_uploaded_image(uuid):
    image_model = image.objects.get(id=uuid)
    image_data_model = imageData.objects.get(id=uuid)
    image_model.delete_image()
    image_data_model.delete()
    return JsonResponse({'success': True})



def flag(request):
    if request.method == 'PUT':
        return HttpResponse("Marshmallow{E3sT3R_3gg!}")
    else:
        return JsonResponse({'Status code': '404'})

def checkLength(kwarg, length):
    if len(kwarg) > length:
        return True
    return False