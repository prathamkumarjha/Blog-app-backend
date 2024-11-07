from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import string
import random
from datetime import timedelta
# Create your models here.
class User(AbstractUser):
    name= models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255, unique=True)
    username = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
  
  
  
class BlogPostManager(models.Manager):
    def active(self):
        return self.filter(is_deleted=False)   
    
     
class BlogPost(models.Model):
    title = models.CharField(max_length=200)
    content= models.TextField() 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)   
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blog_posts')
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    objects = BlogPostManager()
    
    
    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def hard_delete(self):
        
        super(BlogPost, self).delete()     
 
    
class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_At = models.DateTimeField(default=timezone.now() + timedelta(minutes=5))
    
    
    def generate_otp(self):
        otp = ''.join(random.choices(string.digits, k=6))
        return otp
    
    def is_expired(self):
        print("timezonenow", timezone.now())
        print("expiryAt",self.expires_At)
        return timezone.now() > self.expires_At