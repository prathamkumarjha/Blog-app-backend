from django.urls import path
from auth.settings import MEDIA_ROOT
from .views import LikeBlogsView, LoginView, RegisterView, UserView
from .views import BlogPostListView, BlogPostDetailView, ActivateAccount, ChangePassword, ForgotPasswordView, OTPVerificationView, PasswordResetView, MediaUploadView, MyPostsView, BlogPostByTitleView
from rest_framework_simplejwt.views import TokenRefreshView
# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
# )

urlpatterns = [
    #Web APP  
    #Auth
    path('web/auth/register/', RegisterView.as_view()),
    path('web/auth/login/', LoginView.as_view()),
    path('web/auth/verifyemail/<uidb64>/<token>/', ActivateAccount.as_view(), name='activate'),
    path('web/auth/forgotPassword/', ForgotPasswordView.as_view(), name='forgot-password'), 
    path('web/auth/changePassword/<int:id>/', ChangePassword.as_view(), name='change password'), #use this when you remember the password.
    path('web/auth/profile/', UserView.as_view(), name='get_user'),
    path('web/auth/verifyOtp/', OTPVerificationView.as_view(), name='verify-otp'), #otp for forgot password.
    path('web/auth/resetPassword/', PasswordResetView.as_view(), name='reset-password'), #if otp is correct you will be redirected here.
    path('web/auth/upload/', MediaUploadView.as_view(), name='media-upload'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
   #Posts
    path('web/posts/', BlogPostListView.as_view(), name='web-post-list'),  #list all the published posts and also can create a new post if the user is authenticated 
    path('web/myposts',MyPostsView.as_view(), name='my-post-list'), #list all the user posts
    path('web/posts/<int:pk>/', BlogPostDetailView.as_view(), name='post-detail'), #get the specific post  and also can update the new post if the user is authenticated
    path('web/posts/reactions',LikeBlogsView.as_view(), name='liked-posts'),   #Like and dislike a post
    path('web/posts/title/<str:title>/', BlogPostByTitleView.as_view(), name='blogpost-by-title'), #for getting blog post according to its title will be used in search bar 
    #Admin Posts
    #Auth
    path('cms/auth/login/', LoginView.as_view()),
    path('cms/auth/profile/', UserView.as_view(), name='get_user_cms'),
    
    #Posts
    path('cms/posts/', BlogPostListView.as_view(), name='web-post-list_cms'),
    path('cms/posts/<int:pk>/', BlogPostDetailView.as_view(), name='post-detail'), #get the specific post  and also can update the new post if the user is authenticated


    
    #Users
    #I don't know what to write here
]
