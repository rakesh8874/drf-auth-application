from django.urls import path, include
from api import views

urlpatterns = [
    path('register/', views.UserRegistrationView.as_view(), name="api_app"),
    path('login/', views.UserLoginView.as_view(), name="login_api"),
    path('profile/', views.ProfileView.as_view(), name="profile_api"),
    path('changePassword/', views.UserChangedPasswordView.as_view(), name="change_password_api"),
    path('send_reset_password_link/', views.SendPasswordResetEmailView.as_view(), name="send_email_api"),
    path('reset_password/<uid>/<token>/', views.UserPasswordResetView.as_view(), name='reset_password_api')
]
