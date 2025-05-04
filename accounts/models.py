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
    file = models.FileField(upload_to='uploads/', null=True, blank=True)  # Local fallback
    file_url = models.URLField(max_length=1024)  # Signed or public URL
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User_Data, on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        if self.file:
            file_data = self.file.read()
            file_name = self.file.name
            file_path = f"uploads/{self.user.email}/{self.title}/{file_name}"

            # Upload file to Supabase
            upload_response = supabase.storage.from_("uploads").upload(
                file_path,
                file_data,
                file_options={"content-type": self.file.content_type or "application/octet-stream"}
            )

            if upload_response.get("error"):
                raise Exception(f"Upload failed: {upload_response['error']['message']}")

            # Generate a signed URL (valid for 1 hour = 3600 seconds)
            signed_url_data = supabase.storage.from_("uploads").create_signed_url(file_path, 3600)

            if signed_url_data.get("error"):
                raise Exception(f"Signed URL generation failed: {signed_url_data['error']['message']}")

            self.file_url = signed_url_data.get("signedURL")

        super().save(*args, **kwargs)


class CustomUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    github_id = models.CharField(max_length=255, blank=True, null=True)