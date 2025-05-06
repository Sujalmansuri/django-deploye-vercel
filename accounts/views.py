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

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

# Dashboard View (with upload handling)
def dashboard(request):
    if not is_logged_in(request):
        return redirect('login')

    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES["file"]
            title = form.cleaned_data["title"]

            # Validate file type
            allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
            if uploaded_file.content_type not in allowed_types:
                return render(request, "dashboard.html", {
                    "form": form,
                    "files": UploadedFile.objects.filter(user_email=request.session['user_email']),
                    "error": "Invalid file type."
                })

            folder_name = f"user-{request.session['user_email'].split('@')[0]}"
            file_name = f"{uuid.uuid4()}_{uploaded_file.name}"
            file_path = f"{folder_name}/{file_name}"

            try:
                res = supabase.storage.from_(BUCKET_NAME).upload(file_path, uploaded_file, {
                    "content-type": uploaded_file.content_type
                })

                if isinstance(res, dict) and res.get("error"):
                    raise Exception(res["error"])

                public_url = f"https://{SUPABASE_PROJECT_ID}.supabase.co/storage/v1/object/public/{BUCKET_NAME}/{file_path}"

                UploadedFile.objects.create(
                    user_email=request.session['user_email'],
                    title=title,
                    public_url=public_url,
                    path_in_bucket=file_path,
                    file=uploaded_file
                )
                return redirect('dashboard')
            except Exception as e:
                return render(request, "dashboard.html", {
                    "form": form,
                    "files": UploadedFile.objects.filter(user_email=request.session['user_email']),
                    "error": f"Upload failed: {e}"
                })

    else:
        form = UploadFileForm()

    uploaded_files = UploadedFile.objects.filter(user_email=request.session['user_email'])
    return render(request, "dashboard.html", {"form": form, "files": uploaded_files})

# Delete File View
def delete_file(request, file_id):
    if not is_logged_in(request):
        return redirect('login')

    uploaded_file = get_object_or_404(UploadedFile, id=file_id, user_email=request.session['user_email'])

    supabase.storage.from_(BUCKET_NAME).remove([uploaded_file.path_in_bucket])
    uploaded_file.delete()

    return redirect('dashboard')

# Download File View
def download_file(request, file_id):
    if not is_logged_in(request):
        return redirect('login')

    uploaded_file = get_object_or_404(UploadedFile, id=file_id)
    file_path = uploaded_file.path_in_bucket
    response = supabase.storage.from_(BUCKET_NAME).create_signed_url(file_path, 60)
    signed_url = response.get("signedURL")

    if signed_url:
        return redirect(signed_url)
    else:
        return HttpResponse("Failed to generate download link", status=400)
        
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


