from rest_framework import serializers
from .models import Board, Marshmallow_User

class BoardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Board
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Marshmallow_User
        fields = '__all__'
    