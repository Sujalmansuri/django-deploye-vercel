from django.db import models
from django.utils.timezone import now
import os
from supabase import create_client
from django.contrib.auth.models import User 



class User_Data(models.Model):
    full_name = models.CharField(max_length=255, default="")  
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255, null=True, blank=True)  
    is_google_user = models.BooleanField(default=False)  
    created_at = models.DateTimeField(default=now)  

class UploadedFile(models.Model):
    title = models.CharField(max_length=255) 
    public_url = models.URLField()
    path_in_bucket = models.CharField(max_length=255)
    user_email = models.EmailField()
    uploaded_at = models.DateTimeField(auto_now_add=True)  
    
class CustomUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    github_id = models.CharField(max_length=255, blank=True, null=True)

class Notification(models.Model):
    recipient_email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
