import django.conf
from rest_framework import serializers
from auth.settings import BASE_URL
from .models import BlogPost, User, OTP, Media

class BlogPostSerializer(serializers.ModelSerializer):
    likes_count = serializers.IntegerField(read_only=True)  # Add this field to include the number of likes

    class Meta:
        model = BlogPost
        fields = ['id', 'title', 'content', 'created_at', 'updated_at', 'author', 'is_deleted', 'likes_count']
        read_only_fields = ['author']

    def create(self, validated_data):
        print("Initial data:", self.initial_data)  # Debug print
        print("Validated data:", validated_data)  # Debug print
        return BlogPost.objects.create(author=self.context['request'].user, **validated_data)
    
    

class MediaSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Media
        fields = ['id', 'image', 'created_at', 'image_url']

    def get_image_url(self, obj):
        return obj.image_url      
        
class UserSerializer(serializers.ModelSerializer):
    # blog_posts = BlogPostSerializer(many=True, read_only=True)  

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'password'] 
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def __init__(self, *args, **kwargs):
        
        request = kwargs.get('context', {}).get('request', None)
        if request and hasattr(request, 'view'):
            view = request.view
            
            if view and view.action == 'register':
                self.fields.pop('blog_posts')
        super().__init__(*args, **kwargs)

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        if password is None or password == '':
            raise serializers.ValidationError({"password": "Password is required."})

        instance = self.Meta.model(**validated_data)
        instance.set_password(password)
        instance.save()
        return instance


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user is associated with this email address.")
        return value


class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    email = serializers.EmailField()

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError("No user is associated with this email address.")
        
        otp = OTP.objects.filter(user=user, otp=data['otp']).order_by('-id').first()
        if not otp:
            raise serializers.ValidationError("Invalid OTP.")
        
        if otp.is_expired():
            raise serializers.ValidationError("OTP has expired.")
        
        OTP.objects.filter(user=user, otp=data['otp']).delete()
        return data    
    
class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data    