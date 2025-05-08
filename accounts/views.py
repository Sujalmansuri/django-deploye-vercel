from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse, Http404
from .models import User_Data, UploadedFile
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from supabase import create_client
import os
import requests
from django.contrib import messages
from dotenv import load_dotenv
from datetime import datetime
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .forms import UploadFileForm
import uuid
from accounts import views
# Load environment variables from .env file
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
SUPABASE_PROJECT_ID = os.getenv("SUPABASE_PROJECT_ID")  # e.g., 'pwagvdywirofdoqgghkj'
BUCKET_NAME = "uploads"

supabase = create_client(SUPABASE_URL, SUPABASE_API_KEY)

# Ensure OAuth works in dev environment
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from django.shortcuts import redirect
def redirect_if_logged_in(request):
    if request.session.get('user_email'):
        return redirect('dashboard')
    return redirect('login')

# Home Page
def home(request):
    return render(request, 'Home.html')

# Login Page
def login_page(request):
    return render(request, 'login.html')

# Signup Page
def signup_page(request):
    return render(request, 'signup.html')

def dashboard(request):
    user_email = request.session.get('user_email')
    if not user_email:
        return redirect('home')

    query = request.GET.get('q', '')
    files = UploadedFile.objects.all().order_by('-uploaded_at')

    form = UploadFileForm()  # Just an empty form for the upload UI

    if query:
        files = UploadedFile.objects.filter(title__icontains=query).order_by('-uploaded_at')
    else:
        files = UploadedFile.objects.all().order_by('-uploaded_at')

    return render(request, 'dashboard.html', {
        'form': form,
        'files': files,
        'query': query,
        'user_email': user_email
    })

def upload_file(request):
    if request.method == 'POST':
        user_email = request.session.get('user_email')
        if not user_email:
            messages.error(request, "User not logged in.")
            return redirect('login')

        form = UploadFileForm(request.POST, request.FILES)
        if not form.is_valid():
            messages.error(request, "Invalid form submission.")
            return redirect('dashboard')

        file = request.FILES['file']
        title = request.POST.get('title') or file.name
        file_name = file.name
        supabase_bucket = "uploads"

        try:
            # Upload to Supabase
            upload_response = supabase.storage.from_(supabase_bucket).upload(file_name, file.read())
            if getattr(upload_response, 'error', None):
                messages.error(request, f"Upload failed: {upload_response.error.message}")
                return redirect('dashboard')

            public_url = supabase.storage.from_(supabase_bucket).get_public_url(file_name)

            UploadedFile.objects.create(
            title=title,
            public_url=public_url,
            path_in_bucket=file_name,
            user_email=user_email
            )


            messages.success(request, "File uploaded and metadata saved successfully.")
            return redirect('dashboard')

        except Exception as e:
            messages.error(request, f"Upload error: {str(e)}")
            return redirect('dashboard')

    return redirect('dashboard')
def delete_file(request, file_id):
    try:
        file = get_object_or_404(UploadedFile, id=file_id)
        bucket = supabase.storage.from_("uploads")

        # Attempt to delete from Supabase storage
        delete_response = bucket.remove([file.path_in_bucket])

        # Check for errors (if any)
        if isinstance(delete_response, list):
            # Supabase returns a list of deleted file paths
            file.delete()  # Delete from Django DB
            messages.success(request, "File deleted successfully.")
        else:
            messages.error(request, f"Failed to delete from Supabase: {delete_response}")
    except Exception as e:
        messages.error(request, f"Error deleting file: {str(e)}")

    return redirect('dashboard')

# Google Login
def google_login(request):
    flow = Flow.from_client_config(
        client_config=settings.GOOGLE_CREDENTIALS,
        scopes=[
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid'
        ],
        redirect_uri="https://instadatacom.vercel.app/complete/google/",  # Change this as per your setup
    )

    authorization_url, state = flow.authorization_url()
    request.session['state'] = state
    return redirect(authorization_url)

# Google Callback
def google_callback(request):
    flow = Flow.from_client_config(
        settings.GOOGLE_CREDENTIALS,
        scopes=[
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ],
        redirect_uri="https://instadatacom.vercel.app/complete/google/"  # Change this as per your setup
    )

    flow.fetch_token(authorization_response=request.build_absolute_uri())

    credentials = flow.credentials
    try:
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, google_requests.Request()
        )
    except ValueError:
        return redirect("login_page")

    email = id_info.get("email")
    name = id_info.get("name")
    picture = id_info.get("picture")

    user, created = User_Data.objects.get_or_create(
        email=email,
        defaults={
            "full_name": name,
            "is_google_user": True,
            "password": None
        }
    )

    request.session["user_email"] = email
    request.session["user_name"] = name
    request.session["user_picture"] = picture

    return redirect('dashboard')

def signup_submit(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            return render(request, 'signup.html', {'error': 'Passwords do not match!'})

        if User_Data.objects.filter(email=email).exists():
            return render(request, 'signup.html', {'error': 'Email already registered!'})

        user = User_Data.objects.create(
            full_name=full_name,
            email=email,
            password=make_password(password),  # Hash password
            is_google_user=False
        )

        request.session['user_email'] = user.email
        request.session['user_name'] = user.full_name

        return redirect('dashboard')

    return redirect('signup_page')

# Email/Password Login Handler
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User_Data.objects.get(email=email)

            if check_password(password, user.password):
                request.session['user_email'] = user.email
                request.session['user_name'] = user.full_name
                return redirect('dashboard')
            else:
                return render(request, 'login.html', {'error': 'Invalid credentials'})

        except User_Data.DoesNotExist:
            return render(request, 'login.html', {'error': 'User does not exist'})


    return redirect('login_page')


# Login Submit
def login_submit(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User_Data.objects.get(email=email)

            if check_password(password, user.password):
                request.session['user_email'] = user.email
                request.session['user_name'] = user.full_name
                return redirect('dashboard')
            else:
                return render(request, 'login.html', {'error': 'Invalid credentials'})

        except User_Data.DoesNotExist:
            return render(request, 'login.html', {'error': 'User does not exist'})

    return redirect('login_page')


# Logout View
def logout_view(request):
    request.session.flush()
    return redirect('/')  # Ensure 'home' is named properly in urls.py



from supabase import create_client
import time
def download_file(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)
    file_url = uploaded_file.public_url

    try:
        # Fetch file from Supabase
        response = requests.get(file_url, stream=True)
        response.raise_for_status()

        # Use the original filename from path_in_bucket
        filename = uploaded_file.path_in_bucket  # includes extension like .csv

        # Stream the file with correct content-disposition
        django_response = HttpResponse(response.raw, content_type=response.headers.get('Content-Type', 'application/octet-stream'))
        django_response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return django_response

    except requests.RequestException:
        return HttpResponse("Error fetching file.", status=500)
