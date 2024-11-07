from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.permissions import IsAuthenticated
from users.serializers import BlogPostSerializer, ForgotPasswordSerializer, UserSerializer, ForgotPasswordSerializer, PasswordResetSerializer, OTPVerificationSerializer
from .models import User, BlogPost, OTP
from .tokens import account_activation_token
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils import timezone
from datetime import timedelta

# class mu


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
            'user': serializer.data,
        })




class BlogPostListView(generics.ListCreateAPIView):
    queryset = BlogPost.objects.filter(is_deleted=False)
    serializer_class = BlogPostSerializer

    def get_permissions(self):
        if self.request.method == 'GET':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()] 

    def perform_create(self, serializer):
        serializer.save()

class BlogPostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BlogPost.objects.filter(is_deleted=False)
    serializer_class = BlogPostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        serializer.save(author=self.request.user)

    def get_object(self):
        obj = super().get_object()
        if obj.author != self.request.user:
            raise permissions.PermissionDenied("You do not have permission to edit this blog post.")
        return obj

class UserView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user) 
        return Response(serializer.data)

class BlogPostDeleteView(generics.DestroyAPIView):
    queryset = BlogPost.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        post = self.get_object()  
        if request.query_params.get('hard_delete', False):
            post.hard_delete() 
        else:
            post.soft_delete()  
        return Response(status=status.HTTP_204_NO_CONTENT)
    
   
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
        
        password = request.data.get('password')
        new_password = request.data.get('newPassword')
        print(new_password)
        if not request.user.check_password(password):
            raise AuthenticationFailed("Incorrect password")
        if not new_password or not new_password.strip():
            return Response({"message":"New password is required"}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(new_password)
        request.user.save()

        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)

# class ForgotPassword:
#     def post(self, request):

class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(email=serializer.validated_data['email'])
            
            # we are deleting all the past otps 
            OTP.objects.filter(user=user).delete()
            otp = OTP(user=user)
            otp.otp = otp.generate_otp()
            otp.expires_at = (timezone.now() + timedelta(minutes=10))  # OTP expires in 10 minutes
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

