import base64
import json

from django.core import serializers
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
from django.core.mail import send_mail
from django.conf import settings
import jwt

secret_key = config.settings.SECRET_KEY
def user_login(request):
    if request.method == 'POST':
        id = request.POST.get('id')
        password = request.POST.get('password')
        if not id or not password:
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if checkLength(id, 50) or checkLength(password,255):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        try:
            user = Marshmallow_User.objects.get(id=id)
        except Marshmallow_User.DoesNotExist as e:
            return JsonResponse({'error': str(e)})
        stored_password = user.password.encode('utf-8')
        input_password = password.encode('utf-8')
        if bcrypt.checkpw(input_password, stored_password):
            refresh_token = RefreshToken.for_user(user)
            print(type(refresh_token))
            access_token = refresh_token.access_token
            refresh_token.set_exp(lifetime=timedelta(days=1))
            access_token.set_exp(lifetime=timedelta(hours=1))
            refresh_token_encoded = jwt.encode(refresh_token.payload, secret_key, algorithm='HS256')
            access_token_encoded = jwt.encode(access_token.payload, secret_key, algorithm='HS256')
            user.refreshToken = refresh_token_encoded
            user.save()
            response = JsonResponse({
                "success": True,
                "access_token": access_token_encoded,
                "refresh_token": refresh_token_encoded,
            })
            return response
        else:
            return JsonResponse({'success': False},status=401)
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False},status=405)

def user_logout(request):
    if request.method == 'POST':
        refresh_token = request.POST.get('refresh_token')
        if not refresh_token:
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if checkLength(refresh_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if verify_token_signature(refresh_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        try:
            decoded_token = jwt.decode(refresh_token, secret_key, algorithms=['HS256'])
            id = decoded_token.get('user_id')
            user = Marshmallow_User.objects.get(id=id)
            user.refreshToken = None
            user.save()
            return JsonResponse({"success": True})
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False},status=500)

    else:
        return JsonResponse({'error': 'Invalid request Method.', 'success': False},status=405)


def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        id = request.POST.get('id')
        email = request.POST.get('email')
        if not username or not password or not id or not email:
            return JsonResponse({'error':'Invalid Request.', 'success':False},status=400)
        if len(password) > 255:
            return JsonResponse({'error':'Password must be less than 255 digits.', 'success': False}, status=400)
        if len(password) < 10:
            return JsonResponse({'error': 'IPassword must be more than 10 digits.', 'success': False}, status=400)
        if len(id) > 50:
            return JsonResponse({'error': 'ID must be less than 50 digits.', 'success': False}, status=400)
        if len(username) > 100:
            return JsonResponse({'error': 'Username must be less than 100 digits.', 'success': False}, status=400)
        if len(email) > 320:
            return JsonResponse({'error': 'Email must be less than 320 digits.', 'success': False}, status=400)
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
            return JsonResponse({'error': 'id is already exists.', 'success': False},status=400)
        except Marshmallow_User.DoesNotExist:
            pass
        try:
            Marshmallow_User.objects.get(email=email)
            return JsonResponse({'error': 'Email is already exists.', 'success': False},status=400)
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
        return JsonResponse({'error': 'Invalid request method', 'success': False},status=400)

def getAccessToken(request):
    if request.method == 'POST':
        refresh_token_str = request.POST.get('refresh_token')
        if not refresh_token_str:
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if checkLength(refresh_token_str, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if verify_token_signature(refresh_token_str):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        try:
            refresh_token = RefreshToken(refresh_token_str)
            decoded_token = jwt.decode(refresh_token_str, secret_key, algorithms=['HS256'])
            id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False},status=401)
        try:
            access_token = refresh_token.access_token
            access_token.set_exp(lifetime=timedelta(hours=1))
            access_token_encoded = jwt.encode(access_token.payload, secret_key, algorithm='HS256')
            return JsonResponse({'access_token': access_token_encoded})
        except Exception as e:
            return JsonResponse({'error': f'{e}', 'success': False},500)
    else:
        return JsonResponse({'error': 'Invalid request method.', 'success': False},405)


def generate_random_string(length):
    random_bytes = os.urandom(length)
    random_string = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    return random_string[:length]


ResetMail = {}
def send_verification_email(request):
    if request.method == 'POST':
        access_token = request.POST.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            user_id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=user_id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False})
        try:
            reset_token = generate_random_string(32)
            verification_link = f"http://127.0.0.1:8000/api/reset-password/{reset_token}"
            subject = 'Password Reset Verification'
            message = f'Click the following link to reset your password: {verification_link}'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [MarshmallowUser.email]
            send_mail(subject=subject, message=message, from_email=from_email, recipient_list=recipient_list,
                      fail_silently=False)
            ResetMail[f"{reset_token}"] = f"{user_id}"
            print(ResetMail)
            return JsonResponse({'success': True})
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=500)
    else:
        return JsonResponse({'error': "Invalid Method.", 'success': False},status=405)



def reset_password(request,token):
    if request.method == 'GET':
        if ResetMail[f'{token}']:
            if checkLength(token,50):
                return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
            try:
                userid = ResetMail[f'{token}']
                user = Marshmallow_User.objects.get(id=userid)
                init_password = generate_random_string(32)
                salt = bcrypt.gensalt()
                new_password = init_password.encode('utf-8')
                hash_password = bcrypt.hashpw(new_password, salt)
                decode_hash_password = hash_password.decode('utf-8')
                user.password = decode_hash_password
                user.save()
                del ResetMail[f'{token}']
                print(ResetMail)
                return JsonResponse({'success': True, 'New Password': init_password})
            except:
                return JsonResponse({'error': "Verify Failed.", 'success': False}, status=500)
        else:
            return JsonResponse({'error': "Verify Failed.", 'success': False},status=500)
    else:
        return JsonResponse({'error': "Invalid Method.", 'success': False},status=405)






    # 메모 CRUD









def writePost(request):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need an Access Token', 'success': False},status=400)
    if checkLength(access_token,1000):
        return JsonResponse({'error': 'Invalid Request.','success':False},status=400)
    if verify_token_signature(access_token):
        return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
        MarshmallowUser = Marshmallow_User.objects.get(id=user_id)
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}', 'success': False},status=400)
    if request.method == 'POST':  # 게시글 작성
        content = request.POST.get('content')
        hashtag = request.POST.get('hashtag')
        title = request.POST.get('title')
        if not content or not hashtag or not title:
            return JsonResponse({'error': 'Invalid Request.', 'success':False},status=400)
        if checkLength(user_id, 50) or checkLength(title, 255) or checkLength(content, 10000) or checkLength(hashtag,255):
            return JsonResponse({'error': 'Invalid Request.','success':False},status=400)
        try:
            board = article(title=title, content=content, created_by=user_id,hashtag=hashtag,created_at=timezone.now())
            board.save()
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=400)
    else:
        return JsonResponse({'error': 'Invalid Method.', 'success': False}, status=415)


def LoadPost(request):
    if request.method == 'GET':  # 게시글 페이징 , 게시글 다수 조회
        access_token = request.GET.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'You need an Access Token', 'success': False})
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Token.', 'success': False})
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Token.', 'success': False})
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            user_id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=user_id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False})
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
            if page_number > 999999:
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
    elif searchType == 'HASHTAG':
        articles = article.objects.filter(hashtag=searchValue,created_by=userId)
    return JsonResponse({'result': f'{articles}'})




def editPost(request, idx):
    if request.method == 'POST':  # 게시글 수정
        access_token = request.POST.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'You need Access Token', 'success': False},status=400)
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
        try:
            board = article.objects.get(id=idx, created_by=id)
            title = request.POST.get('title')
            contents = request.POST.get('contents')
            hashtag = request.POST.get('hashtag')
            if not title or not contents or not hashtag:
                return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
            if checkLength(title, 255) or checkLength(contents, 10000):
                return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)
            board.modified_at = timezone.now()
            board.title = title
            board.hashtag = hashtag
            board.content = contents
            board.save()
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method', 'success': False},status=400)

def deletePost(request, idx):
    if request.method == 'POST':  # 게시글 삭제
        access_token = request.POST.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'You need Access Token', 'success': False}, status=400)
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if idx > 999999:
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)

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
    if checkLength(access_token,1000):
        return JsonResponse({'error': 'Invalid Token.', 'success': False})
    if verify_token_signature(access_token):
        return JsonResponse({'error': 'Invalid Token.', 'success': False})
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


def image_view(request, uuid):
    request_body = json.loads(request.body)
    access_token = request_body.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token', 'success': False}, status=400)
    if checkLength(access_token, 1000):
        return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
    if verify_token_signature(access_token):
        return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
        MarshmallowUser = Marshmallow_User.objects.get(id=id)
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':
        try:
            if checkLength(uuid, 255):
                return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
            image_obj = imageData.objects.get(id=uuid)
            return HttpResponse(image_obj.data, content_type='image/jpeg')
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
    elif request.method == 'POST':
        try:
            print(uuid)
            if delete_uploaded_image(uuid):
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'error': f'Failed to Delete.', 'success': False}, status=400)

        except Exception as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=400)
    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False}, status=405)



ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp','.heic']

def image_load(request):
    if request.method == 'POST':
        access_token = request.POST.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'You need an Access Token', 'success': False}, status=400)
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=400)
        try:
            image_list = image.objects.filter(created_by=id)
            response = []
            for i in image_list:
                response.append({
                    'id': i.id,
                    'hashtag': i.hashtag,
                    'create_at': i.create_at,
                })
            return JsonResponse({'image_list': response})
        except Exception as e:
            return JsonResponse({'error': f'{e}','success': False},status=400)
    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False}, status=405)

def image_load_with_hashtag(request):
    if request.method == 'POST':
        access_token = request.POST.get('access_token')
        hashtag = request.POST.get('hashtag')
        if not access_token:
            return JsonResponse({'error': 'You need an Access Token', 'success': False}, status=400)
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if checkLength(hashtag, 255) or not hashtag:
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            id = decoded_token.get('user_id')
            MarshmallowUser = Marshmallow_User.objects.get(id=id)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=400)
        try:
            image_list = image.objects.filter(hashtag=hashtag)
            response = []
            for i in image_list:
                response.append({
                    'id': i.id,
                    'hashtag': i.hashtag,
                    'create_at': i.create_at,
                })
            return JsonResponse({'image_list': response})
        except Exception as e:
            return JsonResponse({'error': f'{e}','success': False},status=400)
    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False}, status=405)




def image_upload(request):
    access_token = request.POST.get('access_token')
    if request.method == 'POST':
        if not access_token:
            return JsonResponse({'error': 'You need an Access Token', 'success': False}, status=400)
        if checkLength(access_token, 1000):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        if verify_token_signature(access_token):
            return JsonResponse({'error': 'Invalid Request.', 'success': False}, status=400)
        try:
            decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            created_by = decoded_token.get('user_id')
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
            return JsonResponse({'error': f'{e}', 'success': False}, status=400)
        Realimage = request.FILES.get('image', None)
        Hashtag = request.FILES.get('hashtag', None)
        try:
            if not Realimage:
                return JsonResponse({'error': 'Invalid Request.', 'success': False},status=400)

            file_extension = os.path.splitext(Realimage.name)[1].lower()
            if file_extension not in ALLOWED_EXTENSIONS:
                return JsonResponse({'error': 'Invalid file extension.', 'success': False},status=400)

            file_size = Realimage.size
            max_file_size = 8 * 1024 * 1024
            if file_size > max_file_size:
                return JsonResponse({'error': 'File Maximum size is 8MB.', 'success': False},status=413)

            file_name = Realimage.name
            file_data = Realimage.read()
            UUID = uuid.uuid4()
            file_entity = image(
                id=UUID,
                file_name=file_name,
                file_size=file_size,
                create_at=datetime.datetime.now(),
                is_deleted=False,
                created_by=created_by,
                hashtag=Hashtag
            )
            file_entity.save()
            file_data_entity = imageData(
                id=UUID,
                data=file_data
            )
            file_data_entity.save()
            return JsonResponse({'success': True})

        except ValueError as e:
            return JsonResponse({'error': str(e), 'success':False},status=400)
    else:
        return JsonResponse({'error': 'Invalid Request Method', 'success': False},status=405)


def delete_uploaded_image(uuid):
    image_model = image.objects.filter(id=uuid)
    image_data_model = imageData.objects.filter(id=uuid)
    if not image_model or not image_data_model:
        return False
    image_model.delete()
    image_data_model.delete()
    return True
def flag(request):
    if request.method == 'POST':
        return HttpResponse("Marshmallow{E3sT3R_3gg!}")
    else:
        return JsonResponse({'Status code': '404'})



# 검증 코드



def checkLength(kwarg, length):
    if len(kwarg) > length or len(kwarg) <= 0:
        print(len(kwarg))
        return True
    return False

def verify_token_signature(token):
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'], options={'verify_signature': False})
        header = jwt.get_unverified_header(token)
        payload = decoded_token
        expected_signature = jwt.encode(payload, secret_key, algorithm=header['alg']).split('.')[2]
        actual_signature = token.split('.')[2]
        if expected_signature == actual_signature:
            return False
        else:
            return True

    except jwt.exceptions.DecodeError:
        return True
