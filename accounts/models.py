from django.db import models
from django.utils.timezone import now
import os
from supabase import create_client

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

    
class UploadedFile(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User_Data, on_delete=models.CASCADE)

    
    def upload_to_supabase(self, file):
        """ Upload file to Supabase Storage and store the file URL """
        file_path = f"uploads/{self.user.email}/{self.title}/{file.name}"

        # Upload the file to Supabase
        upload_response = supabase.storage.from_('uploads').upload(file_path, file)

        if upload_response.get("error"):
            raise Exception(f"Error uploading file: {upload_response['error']['message']}")

        # Get the file URL
        self.file_url = supabase.storage.from_('uploads').get_public_url(file_path)["publicURL"]
        self.save()
        
class CustomUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    github_id = models.CharField(max_length=255, blank=True, null=True)