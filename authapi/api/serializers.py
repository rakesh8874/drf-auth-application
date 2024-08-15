from rest_framework import serializers
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class UserRegistrationSerializer(serializers.ModelSerializer):

    confirmpassword = serializers.CharField(style={'input_type':'password'},write_only=True)

    class Meta:
        model = User
        fields = ['email','name','password','confirmpassword','tc']
        extra_kwargs = {
            'password':{'write_only':True} 
        } 

    def validate(self, attrs):
        password = attrs.get('password')
        confirmpassword = attrs.get('confirmpassword')
        if password != confirmpassword:
            raise serializers.ValidationError("Password and Confirm Password Doesn't Match")
        return attrs
    

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)    


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User    
        fields = ['email','password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','email','name','tc']


class ChangedPasswordSerializer(serializers.Serializer):
     password = serializers.CharField(max_length = 255, style = {'input-type':'password'}, write_only=True)
     confirmpassword = serializers.CharField(max_length = 255, style={'input-type':'password'}, write_only = True)
     class Meta:
         fields = ['password','confirmpassword']

     def validate(self, attrs):
        password = attrs.get('password')
        confirmpassword = attrs.get('confirmpassword')
        user = self.context.get('user')
        if password != confirmpassword:
            raise serializers.ValidationError("Password and Confirm Password Doesn't Match")
        user.set_password(password)
        user.save()
        return attrs
        

class SendPasswordResetEmailViewSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("encoded uid ", uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("password reset token ", token)
            link = "http://localhost:3000/api/user/reset/"+uid+"/"+token
            print("Password Reset Link ", link)
            # Send Email
            body = 'Click Following Link To Reset Your Password '+link
            data = {
                'subject':'Reset Your Password',
                'body':body,
                'to_email':user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValueError("You Are Not A Registered User")
    
class UserResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style = {'input-type':'password'}, write_only=True)
    confirmpassword = serializers.CharField(max_length = 255, style={'input-type':'password'}, write_only = True)
    class Meta:
         fields = ['password','confirmpassword']

    def validate(self, attrs):
       try:
            password = attrs.get('password')
            confirmpassword = attrs.get('confirmpassword')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != confirmpassword:
                raise serializers.ValidationError("Password and Confirm Password Doesn't Match")
            id  = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token isn't valid or Expired ")
            user.set_password(password)
            user.save()
            return attrs
       except DjangoUnicodeDecodeError as indentifier:
           PasswordResetTokenGenerator().check_token(user, token) 
           raise serializers.ValidationError("Token isn't valid or Expired ")
       

   

class AuthTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['name'] = user.name
        token['tc'] = user.tc
        return token


