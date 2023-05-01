from django.contrib.auth.models import UserManager
from django.db import models
from django.contrib.auth.hashers import check_password as django_check_password


# Create your models here.
class Marshmallow_User(models.Model): #유저 모델
    id = models.CharField(max_length=50, null=False,primary_key=True)
    password = models.CharField(max_length=150,null=False)
    name = models.CharField(max_length=100,null=False)
    email = models.EmailField(max_length=150,null=False)
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


class Board(models.Model): #게시글 모델
    idx = models.IntegerField(null=False,primary_key=True)
    title = models.CharField(max_length=255,null=False)
    contents = models.CharField(max_length=3000,null=False)
    password = models.CharField(max_length=255)
    @classmethod
    def create_board(cls, **kwargs):
        return cls.objects.create(**kwargs)

    @classmethod
    def get_board(cls, idx):
        try:
            return cls.objects.get(idx=idx)
        except cls.DoesNotExist:
            return None

    @classmethod
    def delete_board(self):
        self.delete()

    @classmethod
    def search_posts(cls, keyword):
        return cls.objects.filter(title__icontains=keyword)

#모델 구현