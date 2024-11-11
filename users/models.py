from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import string
import random
# from datetime import timedelta
from django.conf import settings
# Create your models here.
class User(AbstractUser):
    
    class DesignationChoices(models.TextChoices):
        ADMIN = 'Admin', 'Admin'
        SUPER_ADMIN = 'Super Admin', 'Super Admin'
        USER = 'User', 'User'
       
    name= models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    designation = models.CharField(
        max_length=50,
        choices=DesignationChoices.choices,
        default=DesignationChoices.USER,
    ) 
    image= models.CharField(blank=True, null=True)
    username = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
  
  

class BlogPostManager(models.Manager):
    def active(self):
        return self.filter(is_deleted=False)   
    
     
class BlogPost(models.Model):
    title = models.CharField(max_length=200)
    summary = models.CharField(max_length=250, default="no summary")
    content= models.TextField() 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)   
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blog_posts')
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    objects = BlogPostManager()
    thumbnail = models.TextField()
    
    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def hard_delete(self):
        super(BlogPost, self).delete()     
 
class Media(models.Model):
    image = models.ImageField(upload_to='media/')
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def image_url(self):
        return f"{settings.BASE_URL}{self.image.url}"

    def __str__(self):
        return self.image.url 
      
class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_At = models.DateTimeField()
    
    
    def generate_otp(self):
        otp = ''.join(random.choices(string.digits, k=6))
        return otp
    
    def is_expired(self):
        print("timezonenow", timezone.now())
        print("expiryAt",self.expires_At)
        
        return timezone.now() > self.expires_At
    
class LikedBlogs(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    blogpost = models.ForeignKey(BlogPost, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'blogpost'], name='unique_user_blogpost_like')
        ]

    def __str__(self):
        return f"User {self.user} liked BlogPost {self.blogpost.id}"
        