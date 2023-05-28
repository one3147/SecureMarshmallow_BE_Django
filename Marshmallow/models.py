import uuid
from datetime import timezone

from django.contrib.auth.models import UserManager
from django.db import models
from django.contrib.auth.hashers import check_password as django_check_password
from django.utils import timezone

# Create your models here.
class Marshmallow_User(models.Model): #유저 모델
    id = models.CharField(max_length=50, null=False,primary_key=True)
    password = models.CharField(max_length=255,null=False)
    name = models.CharField(max_length=100,null=False)
    email = models.EmailField(max_length=320,null=False)
    USERNAME_FIELD = 'id'
    REQUIRED_FIELDS = []
    @property
    def is_authenticated(self):
        return True
    @property
    def is_anonymous(self):
        return False

    objects = UserManager()

    def get_by_natural_key(self, username):
        return self.get(**{self.USERNAME_FIELD: username})
    def check_password(self, raw_password):
        return django_check_password(raw_password, self.password)


class article(models.Model):
    id = models.BigAutoField(primary_key=True)
    created_at = models.DateTimeField()
    created_by = models.CharField(max_length=100)
    modified_at = models.DateTimeField(null=True)
    content = models.CharField(max_length=10000)
    hashtag = models.CharField(max_length=255, null=True)
    title = models.CharField(max_length=255)
    @classmethod
    def create_board(cls, **kwargs):
        return cls.objects.create(**kwargs)
    @classmethod
    def get_board(cls, idx,id):
        try:
            return cls.objects.get(idx=idx,id=id)
        except cls.DoesNotExist:
            return None
    def delete_board(self):
        self.delete()
    @classmethod
    def search_posts(cls, keyword,id):
        result = cls.objects.filter(title__icontains=keyword,id=id)
        result += cls.objects.filter(hashtag__icontains=keyword, id=id)
        return result
    def __str__(self):
        return str(self.title)


class image(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_at = models.DateTimeField(null=True, default=timezone.now)
    file_name = models.CharField(max_length=255, null=True)
    file_size = models.BigIntegerField(null=True)
    is_deleted = models.BooleanField(null=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.file_name

    def delete_image(self):
        self.delete()

class imageData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    data = models.BinaryField()

    def __str__(self):
        return str(self.id)
    def delete(self):
        self.delete()