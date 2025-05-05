from django.db import models
from django.utils.timezone import now
import os
from supabase import create_client
from django.contrib.auth.models import User 

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_API_KEY)

class User_Data(models.Model):
    full_name = models.CharField(max_length=255, default="")  # Add a default value
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255, null=True, blank=True)  # For password login
    is_google_user = models.BooleanField(default=False)  # To track Google login users
    created_at = models.DateTimeField(default=now)  # Corrected from previous error
# models.py

class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    public_url = models.URLField()
    path_in_bucket = models.CharField(max_length=500)  # <- NEW FIELD
    uploaded_at = models.DateTimeField(auto_now_add=True)


class CustomUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    github_id = models.CharField(max_length=255, blank=True, null=True)