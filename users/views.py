from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.permissions import IsAuthenticated
from users.serializers import BlogPostSerializer, ForgotPasswordSerializer, UserSerializer, ForgotPasswordSerializer, PasswordResetSerializer, OTPVerificationSerializer, MediaSerializer
from .models import User, BlogPost, OTP
from .tokens import account_activation_token
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils import timezone
from datetime import timedelta
from .models import Media
from rest_framework.generics import ListAPIView
from django.db.models import Count
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound, PermissionDenied
from django.db.models import Q
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.is_active = False
        user.save()
        token = account_activation_token.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        activation_link = request.build_absolute_uri(
            reverse('activate', kwargs={'uidb64': uid, 'token': token})
        )
        
        send_mail(
            'Activate your account',
            f'Click the link to verify your account: {activation_link}',
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )
        return Response({"message": "Please check your email to activate your account."}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found')

        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect password")

        if not user.is_active:
            raise AuthenticationFailed("Email not verified. Please verify your email to activate your account.")

        refresh = RefreshToken.for_user(user)
        serializer = UserSerializer(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            "message": "logged in successfully"
        })





class BlogPostListView(generics.ListCreateAPIView):
    queryset = BlogPost.objects.filter(is_deleted=False, is_archived=False).select_related('author').order_by('-created_at')
    serializer_class = BlogPostSerializer

    def get_permissions(self):
        if self.request.method == 'GET':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()] 
    def get_queryset(self):
        return BlogPost.objects.annotate().filter(is_deleted=False, is_archived=False).select_related('author').order_by('-created_at')
        
    def perform_create(self, serializer):
        serializer.save()

class BlogPostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BlogPost.objects.filter(is_deleted=False).select_related('author').order_by('-created_at')
    serializer_class = BlogPostSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]  # Anyone can read, authenticated users can edit

    def get_object(self):
        # Retrieve the object, allowing access to soft-deleted items for PATCH and DELETE requests
        if self.request.method in ['DELETE', 'PATCH']:
            obj = BlogPost.objects.filter(id=self.kwargs['pk']).first()  # Retrieve even soft-deleted posts
        else:
            obj = super().get_object()  # Use the default queryset filtering for non-deleted posts
        
        # If the object is not found, raise a NotFound error
        if not obj:
            raise NotFound("Blog post not found.")

        # Restrict edit and delete permissions to the author or Super Admin
        if self.request.method in ['PUT', 'PATCH', 'DELETE']:
            if obj.author != self.request.user and self.request.user.designation != "Super Admin":
                raise PermissionDenied("You do not have permission to edit or delete this blog post.")
        
        return obj


class BlogPostAuthDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BlogPost.objects.filter(is_deleted=False).select_related('author').order_by('-created_at')
    serializer_class = BlogPostSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]  # Anyone can read, authenticated users can edit

    def get_object(self):
        # Retrieve the object, allowing access to soft-deleted items for PATCH and DELETE requests
        if self.request.method in ['DELETE', 'PATCH']:
            obj = BlogPost.objects.filter(id=self.kwargs['pk']).first()  # Retrieve even soft-deleted posts
        else:
            obj = super().get_object()  # Use the default queryset filtering for non-deleted posts
        
        # If the object is not found, raise a NotFound error
        if not obj:
            raise NotFound("Blog post not found.")


        # Restrict read access for GET requests to the author
        if self.request.method == 'GET':
            if obj.author != self.request.user and self.request.user.designation != "Super Admin":
                raise PermissionDenied("You do not have permission to view this blog post.")

        # Restrict edit and delete permissions to the author or Super Admin
        if self.request.method in ['PUT', 'PATCH', 'DELETE']:
            if obj.author != self.request.user and self.request.user.designation != "Super Admin":
                raise PermissionDenied("You do not have permission to edit or delete this blog post.")
        
        return obj

    def perform_update(self, serializer):
        # Allow only the author to update the post
        serializer.save(author=self.request.user)

    def perform_destroy(self, instance):
        if instance.author != self.request.user and self.request.user.designation != "Super Admin":
            raise PermissionDenied("You do not have permission to delete this post.")
        
        # Handle soft delete or permanent delete
        if instance.is_deleted:
            instance.delete()
            return Response({'message': 'Post deleted permanently'})
        else:
            instance.is_deleted = True
            instance.deleted_at = timezone.now()
            instance.save()
            return Response({'message': 'Post moved to trash'})





    def perform_update(self, serializer):
        # Allow only the author to update the post
        serializer.save(author=self.request.user)

    def perform_destroy(self, instance):
        if instance.author != self.request.user and self.request.user.designation != "Super Admin":
            raise PermissionDenied("You do not have permission to delete this post.")
        
        # Handle soft delete or permanent delete
        if instance.is_deleted:
            instance.delete()
            return Response({'message': 'Post deleted permanently'})
        else:
            instance.is_deleted = True
            instance.deleted_at = timezone.now()
            instance.save()
            return Response({'message': 'Post moved to trash'})

class BlogPostSearchView(APIView):
    def get(self, request):
        search_term = request.query_params.get('q', '')
        if search_term:
            posts = BlogPost.objects.filter(
                Q(title__icontains=search_term) | Q(summary__icontains=search_term),
                is_deleted=False, is_archived=False
            )
        else:
             return Response(status=status.HTTP_204_NO_CONTENT)
        serialized_posts = BlogPostSerializer(posts, many=True)
        return Response(serialized_posts.data)
    
class UserView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        # Get the user object for the authenticated user
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)


    def patch(self, request):
        # Update the user information with the data from the request
        user = request.user

        # Validate and update fields. Assuming the serializer handles validation.
        serializer = UserSerializer(user, data=request.data, partial=True)  # Use partial=True for partial update
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=200)
        return Response(serializer.errors, status=400) 
        
   
class ActivateAccount(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Account activated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Activation link is invalid!'}, status=status.HTTP_400_BAD_REQUEST)

class ChangePassword(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, id):
        
        if request.user.id != id:
            return Response({"error": "You are not authorized to change this password."}, status=status.HTTP_403_FORBIDDEN)
        
        password = request.data.get('currentPassword')
        new_password = request.data.get('newPassword')
        print(new_password)
        if not request.user.check_password(password):
            raise AuthenticationFailed("Incorrect password")
        if not new_password or not new_password.strip():
            return Response({"message":"New password is required"}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(new_password)
        request.user.save()

        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(email=serializer.validated_data['email'])
            
            # we are deleting all the past otps 
            OTP.objects.filter(user=user).delete()
            otp = OTP(user=user)
            otp.otp = otp.generate_otp()
            otp.expires_At = (timezone.now() + timedelta(minutes=10))  # OTP expires in 10 minutes
            print(timezone.now())
          
            otp.save()
            
            # Send OTP to user's email
            send_mail(
                'Password Reset OTP',
                f'Your OTP is {otp.otp}. It will expire in 10 minutes.',
                'from@example.com',
                [user.email],
                fail_silently=False,
            )
            return Response({"message": "OTP sent to email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class OTPVerificationView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(email=serializer.validated_data['email'])
            
            # Generate refresh token after OTP verification
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            return Response({
                "message": "OTP verified. You can now reset your password.",
                "refresh_token": str(refresh),  # Send refresh token to the client
                # "access_token": access_token  # Optional: Send access token
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(APIView):
    def post(self, request):
        token = request.data.get('token')  # Get the refresh token
        user = self.get_user_from_token(token)
        
        if not user:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            user.set_password(serializer.validated_data['password'])
            user.save()
            return Response({"message": "Password has been reset."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_user_from_token(self, token):
        try:
            # Use RefreshToken for verification of the refresh token
            print(RefreshToken(token))
            payload = RefreshToken(token).payload
            user_id = payload.get('user_id')
            return User.objects.get(id=user_id)
        except Exception:
            return None


class MediaUploadView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        serializer = MediaSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
  
    
class MyPostsView(generics.ListAPIView):
    serializer_class = BlogPostSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        user = self.request.user
        return BlogPost.objects.filter(author=user).order_by('-created_at')        
    
    
class IncreaseClapsView(APIView):
    permission_classes=[IsAuthenticated]
    
    def patch(self, request, pk):
        try:
            blog_post = BlogPost.objects.get(pk=pk, is_deleted=False)
            blog_post.claps += 1
            blog_post.save()
            
            return Response({"claps":blog_post.claps},status=status.HTTP_200_OK)
        except BlogPost.DoesNotExist:
            return Response({"error": "Blog post not found"}, status=status.HTTP_404_NOT_FOUND)