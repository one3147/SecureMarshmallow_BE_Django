import jwt
from django.core.exceptions import ObjectDoesNotExist

import config
from Marshmallow.models import Board
import secrets
import string
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


def writeOrViewPost(request):
    access_token = request.POST.get('access_token') or request.GET.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}', 'success': False})
    if request.method == 'POST':  # 게시글 작성
        idx = request.POST.get('idx')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
        try:
            if len(id) > 50:
                raise Exception('id must be less than 50 digits.')
            if len(title) > 255:
                raise Exception('title must be less than 255 digits.')
            if len(contents) > 3000:
                raise Exception('contents must be less than 3000 digits.')
            if len(password) > 255:
                raise Exception('password must be less than 255 digits.')
        except Exception as e:
            return JsonResponse({'error': str(e)})
        if password:
            salt = bcrypt.gensalt()
            new_password = password.encode('utf-8')
            hash_password = bcrypt.hashpw(new_password, salt)
            decode_hash_password = hash_password.decode('utf-8')
            board = Board(idx=idx, title=title, contents=contents, password=decode_hash_password, id=id)
        else:
            board = Board(idx=idx, title=title, contents=contents, id=id)
        board.save()
        return JsonResponse({'success': True})
    elif request.method == 'GET':  # 게시글 페이징 , 게시글 다수 조회
        try:
            if len(id) > 50:
                raise Exception('id must be less than 50 digits.')
        except Exception as e:
            return JsonResponse({'error': str(e)})
        paginator = Paginator(Board.objects.filter(id=id), 10)
        page_number = request.GET.get('number')
        if not page_number:
            page_number = 1
        page_obj = paginator.get_page(page_number)
        posts = page_obj.object_list
        if not posts:
            return JsonResponse({'error': 'No posts', 'success': False})
        response_data = {
            'count': len(posts),
            'num_pages': page_number,
            'posts': [{'idx': post.idx, 'title': post.title, 'id': post.id} for post in posts],
        }
        return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False})




def Post(request, idx):
    access_token = request.GET.get('access_token') or request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':  # 게시글 단일 조회
        try:
            if len(id) > 50:
                raise Exception('id must be less than 50 digits.')
        except Exception as e:
            return JsonResponse({'error': f'{str(e)}'})
        try:
            post = Board.objects.get(idx=idx, id=id)
            return JsonResponse({'success': 'True', 'idx': f'{idx}', 'post': f'{post}', 'title': f'{post.title}',
                                 'contents': f'{post.contents}', 'password': f'{post.password}'})
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    elif request.method in ['POST'] and not request.POST.get('delete'):  # 게시글 수정
        try:
            if len(id) > 50:
                raise Exception('id must be less than 50 digits.')
            if not id:
                raise Exception('Missing id.')
        except Exception as e:
            return JsonResponse({'error': str(e)})
        try:
            board = Board.objects.get(idx=idx, id=id)
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist.', 'success': False})
        title = request.POST.get('title') or board.title
        contents = request.POST.get('contents') or board.contents
        password = request.POST.get('password') or board.password
        try:
            if len(title) > 255:
                raise Exception('title must be less than 255 digits.')
            if len(contents) > 3000:
                raise Exception('contents must be less than 3000 digits.')
            if len(password) > 255:
                raise Exception('password must be less than 255 digits.')
        except Exception as e:
            return JsonResponse({'error': str(e)})
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
        password = request.POST.get('password')
        try:
            if len(password) > 255:
                raise Exception('Password must be less than 255 digits.')
            if len(id) > 50:
                raise Exception('id must be less than 50 digits.')
        except Exception as e:
            return JsonResponse({'error': str(e)})

        board = Board.objects.get(idx=idx, id=id)
        if board is None:
            return JsonResponse({'error': 'Post does not exist.', 'success': False})
        elif board.password != password:
            return JsonResponse({'error': 'Wrong password.', 'success': False})
        else:
            board.delete_board()
            return JsonResponse({'Delete': True})
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False})


def search_posts(request):
    access_token = request.GET.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':
        search_word = request.GET.get('search_word')
        try:
            if len(id) > 50:
                raise Exception('id must be less than 50 digits.')
            if len(search_word) > 300:
                raise Exception('search word must be less than 300 digits.')
        except Exception as e:
            return JsonResponse({'error': str(e)})
        posts = Board.search_posts(search_word, id)
        return JsonResponse({'result': f'{posts}'})
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False})



def CreatePassword(request):
    if request.method == 'POST':
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        return JsonResponse({'Password': f"{password}"})
    else:
        return JsonResponse({'error': 'Invalid request method'})


def profile(request):
    access_token = request.POST.get('access_token')
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    if request.method == 'POST':
        try:
            if len(id) > 50:
                raise ValueError('id must be less than 50 digits.')
        except ValueError as e:
            return JsonResponse({'error': str(e)})
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist as e:
            return JsonResponse({'error': f'{str(e)}'})
        return JsonResponse({'user': f'{user}'})
    else:
        return JsonResponse({'error': 'Invalid request method.'})


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
    else:
       delete_uploaded_image(uuid,id)

ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp','.heic']

def image_load(request):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need an Access Token', 'success': False})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    image_list = image.objects.get()
    response = ""
    for i in image_list:
        response += i
    return JsonResponse({'image_list': response})

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
                file_id=UUID,
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


def delete_uploaded_image(uuid, user_id):
    image_model = image.objects.get(id=uuid)
    image_data_model = imageData.objects.get(id=user_id)
    image_model.delete_image()
    image_data_model.delete()
    return JsonResponse({'success': True})



def flag(request):
    if request.method == 'PUT':
        return HttpResponse("Marshmallow{E3sT3R_3gg!}")
    else:
        return JsonResponse({'Status code': '404'})