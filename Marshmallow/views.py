import jwt
from Marshmallow.models import Marshmallow_User, Board, image
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
secret_key = 'django-insecure-(rt$j6+-i0u&1rg4%@li)n5-2ln85uyk(y7u4a+m^0t+szmpv*'
def user_login(request):
    if request.method == 'GET':
        id = request.GET.get('id')
        password = request.GET.get('password')
        if len(id) > 50 or len(password) > 255:
            return JsonResponse({'error': 'id or Password is too Long.'})
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
                "message": "login success",
                "access_token": access_token_encoded,
                "refresh_token": refresh_token_encoded,
            })
            return response
        else:
            return JsonResponse({'success': 'fail to login'})

def user_logout(request):
    if request.method == 'POST':
        response = JsonResponse({"success": True})
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

    else:
        return JsonResponse({'error': 'Invalid request Method.'})


def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        id = request.POST.get('id')
        email = request.POST.get('email')
        if len(password) > 255:
            return JsonResponse({'error' : 'Password must be less than 255 digits.'})
        if len(password) < 10:
            return JsonResponse({'error' : 'Password must be more than 10 digits.'})
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if len(username) > 100:
            return JsonResponse({'error': 'Username must be less than 100 digits.'})
        if len(email) > 320:
            return JsonResponse({'error': 'Email must be less than 320 digits.'})

        if not re.search(r'\d', password):
            return JsonResponse({'error' : 'Password must contains Number.'})
        if not re.search(r'[a-zA-Z]', password):
            return JsonResponse({'error' : 'Password must contains Alphabet.'})
        if not re.search(r"[!@#$%^&*()\-=_+[\]{};':\"|,.<>/?]+", password):
            return JsonResponse({'error' : 'Password must contains special symbol.'})
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
    access_token = request.POST.get('access_token') or request.GET.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':  # 게시글 작성
        idx = request.POST.get('idx')
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        password = request.POST.get('password')
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if len(title) > 255:
            return JsonResponse({'error': 'title must be less than 255 digits.'})
        if len(contents) > 3000:
            return JsonResponse({'error': 'contents must be less than 3000 digits.'})
        if len(password) > 255:
            return JsonResponse({'error': 'password must be less than 255 digits.'})
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
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        paginator = Paginator(Board.objects.filter(id=id), 10)
        page_number = request.GET.get('number')
        if not page_number:
            page_number = 1
        page_obj = paginator.get_page(page_number)
        posts = page_obj.object_list
        if not posts:
            return JsonResponse({'error': 'No posts'})
        response_data = {
            'count': len(posts),
            'num_pages': page_number,
            'posts': [{'idx': post.idx, 'title': post.title, 'id': post.id} for post in posts],
        }
        return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Invalid request method'})




def Post(request, idx):
    access_token = request.GET.get('access_token') or request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':  # 게시글 단일 조회
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        try:
            post = Board.objects.get(idx=idx, id=id)
            return JsonResponse({'success': 'True', 'idx': f'{idx}', 'post': f'{post}', 'title': f'{post.title}',
                                 'contents': f'{post.contents}', 'password': f'{post.password}'})
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})
    elif request.method in ['POST'] and not request.POST.get('delete'):  # 게시글 수정
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if not id:
            return JsonResponse({'error': 'with id'})
        try:
            board = Board.objects.get(idx=idx, id=id)
        except Board.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist.'})
        title = request.POST.get('title') or board.title
        contents = request.POST.get('contents') or board.contents
        password = request.POST.get('password') or board.password
        if len(title) > 255:
            return JsonResponse({'error': 'title must be less than 255 digits.'})
        if len(contents) > 3000:
            return JsonResponse({'error': 'contents must be less than 3000 digits.'})
        if len(password) > 255:
            return JsonResponse({'error': 'password must be less than 255 digits.'})
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
        if len(password) > 255:
            return JsonResponse({'error': 'Password must be less than 255 digits.'})
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
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
    access_token = request.GET.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'GET':
        search_word = request.GET.get('search_word')
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if len(search_word) > 300:
            return JsonResponse({'error': 'search word must be less than 300 digits.'})
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
    access_token = request.POST.get('access_token')
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    if request.method == 'POST':
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
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
        if len(refresh_token) > 100:
            return JsonResponse({'error': 'Refresh Token\'s length is too long.'})
        if refresh_token:
            access_token = refresh_token.access_token
            access_token.set_exp(lifetime=timedelta(hours=1))
            access_token_encoded = jwt.encode(access_token.payload, secret_key, algorithm='HS256')
            response = JsonResponse({'access_token': access_token_encoded})
            return response
        else:
            return JsonResponse({'error': "You don't Have RefreshToken."})
    else:
        return JsonResponse({'error': 'Invalid request method.'})

def filename_filter(filename):
    pattern = r'^[\w\s\'-가-힣]+$'
    return re.match(pattern, filename) is not None


def image_View(request):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':
        filename = request.POST.get('filename')
        if filename in "../":
            return JsonResponse({'error': 'Invalid filename.'})
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if len(filename) > 255:
            return JsonResponse({'error': 'filename must be less than 255 digits.'})

        if not filename_filter(filename):
            return JsonResponse({'error': 'Invalid filename.'})

        file_path = os.path.join(settings.MEDIA_ROOT, 'images', filename)
        try:
            image_obj = image.objects.get(image=filename, id=id)
        except image.DoesNotExist:
            return JsonResponse({'error': 'Post does not exist'})

        if os.path.exists(file_path):
            with open(file_path, 'rb') as image_file:
                response = HttpResponse(image_file.read(), content_type='image/*')
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
        else:
            return JsonResponse({'error': 'File not found'})
    else:
        return JsonResponse({'error': 'Invalid Request Method'})


ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp','.heic']
def image_upload(request):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':
        Realimage = request.FILES.get('image', None)
        if len(id) > 50:
            return JsonResponse({'error': 'id must be less than 50 digits.'})
        if Realimage:
            try:
                file_extension = os.path.splitext(Realimage.name)[1].lower()
                if file_extension not in ALLOWED_EXTENSIONS:
                    return JsonResponse({'error': 'Invalid file extension.'})
                file_size = Realimage.size
                max_file_size = 8 * 1024 * 1024
                if file_size > max_file_size:
                    return JsonResponse({'error': 'File Maximum size is 8mb.'})
                save_path = './media/images/'
                file_name = Realimage.name
                file_path = os.path.join(save_path, file_name)
                imageModel = image(id=id, image=file_name)
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
        return JsonResponse({'error': 'Invalid Request Method'})


def delete_uploaded_image(request):
    access_token = request.POST.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'You need Access Token'})
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        id = decoded_token.get('user_id')
    except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) as e:
        return JsonResponse({'error': f'{e}'})
    if request.method == 'POST':
        filename = request.POST.get('filename')
        if filename in "../":
            return JsonResponse({'error': 'Invalid filename.'})
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