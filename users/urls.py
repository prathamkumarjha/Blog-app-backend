from django.urls import path
from .views import RegisterView, LoginView, UserView 
from .views import BlogPostListView, BlogPostDetailView, BlogPostDeleteView, ActivateAccount, ChangePassword, ForgotPasswordView, OTPVerificationView, PasswordResetView
# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
# )

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('cms/posts/', BlogPostListView.as_view(), name='post-list'),
    path('web/posts/', BlogPostListView.as_view(), name='web-post-list'),
    path('user/', UserView.as_view(), name='get_user'),
    path('posts/', BlogPostListView.as_view(), name='post-list'), 
    # path('myposts/')
    path('posts/<int:pk>/', BlogPostDetailView.as_view(), name='post-detail'), 
    path('deletePosts/<int:pk>/', BlogPostDeleteView.as_view(), name='blogpost-delete'),
    path('verifyemail/<uidb64>/<token>/', ActivateAccount.as_view(), name='activate'), 
    path('changePassword/<int:id>/', ChangePassword.as_view(), name='change password'),
    path('forgotPassword/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('verifyOtp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('resetPassword/', PasswordResetView.as_view(), name='reset-password'),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
