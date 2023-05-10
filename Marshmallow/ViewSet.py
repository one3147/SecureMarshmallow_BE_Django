from rest_framework import viewsets
from .models import Board,Marshmallow_User
from .serializers import BoardSerializer,UserSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = Marshmallow_User.objects.all()
    serializer_class = UserSerializer

class BoardViewSet(viewsets.ModelViewSet):
    queryset = Board.objects.all()
    serializer_class = BoardSerializer