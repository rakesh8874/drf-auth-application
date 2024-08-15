from django.shortcuts import render
from . models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from rest_framework import status
from django.contrib.auth import authenticate
from .renderers import UserRendrer
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.permissions import IsAuthenticated
import jwt
from django.conf import settings

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    # auth_token = jwt.encode({'email':user.email, 'name':user.name, 'tc':user.tc}, settings.JWT_SECRET_KEY)

    return {
        'refresh':str(refresh),
        'access':str(refresh.access_token)
    }

# Create your views here.
class UserRegistrationView(APIView):
    renderer_classes = [UserRendrer]
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.save()
        # token =  get_tokens_for_user(user)
            refresh = AuthTokenObtainPairSerializer.get_token(user)
            return Response({'refresh':str(refresh), 'access':str(refresh.access_token), "msg":"Registration Success"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLoginView(APIView):
    renderer_classes = [UserRendrer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                # token =  get_tokens_for_user(user)
                refresh = AuthTokenObtainPairSerializer.get_token(user)
                return Response({'refresh':str(refresh), 'access':str(refresh.access_token), "msg":"Login Success"}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_fields_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)   

class ProfileView(APIView):
    renderer_classes = [UserRendrer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserChangedPasswordView(APIView):
    renderer_classes = [UserRendrer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = ChangedPasswordSerializer(data = request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg":"Password Changed Succesfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRendrer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailViewSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Link Sent on Your Email Id'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserPasswordResetView(APIView):
    renderer_classes = [UserRendrer]
    def post(self, request, uid, token, format=None):
        serializer = UserResetPasswordSerializer(data=request.data, context={'uid':uid, 'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg":"Password Reset Successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


        

