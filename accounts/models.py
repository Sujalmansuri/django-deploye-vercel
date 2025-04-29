
from django.utils.timezone import now
from django.db import models

class User_Data(models.Model):
    full_name = models.CharField(max_length=255, default="")  # Add a default value
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255, null=True, blank=True)  # For password login
    is_google_user = models.BooleanField(default=False)  # To track Google login users
    created_at = models.DateTimeField(default=now)  # Corrected from previous error

    
class UploadedFile(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User_Data, on_delete=models.CASCADE)

    
class CustomUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    github_id = models.CharField(max_length=255, blank=True, null=True)