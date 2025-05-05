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
# Load environment variables from .env file
load_dotenv()

# Supabase Client Setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_API_KEY)

# Ensure OAuth works in dev environment
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Redirect if already logged in
def redirect_if_logged_in(request):
    if request.session.get('user_email'):
        return redirect('dashboard')

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


def dashboard(request):
    if 'user_email' not in request.session:
        return redirect('login')

    user_email = request.session['user_email']
    filter_type = request.GET.get('filter', 'myfiles')

    # Handle file upload
    success = error = None
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            # Manual file processing instead of form.save()
            file = request.FILES["file"]
            file_title = form.cleaned_data["title"]

            try:
                user = User_Data.objects.get(email=user_email)
                file_data = file.read()
                file_path = f"{user.id}/{datetime.now().timestamp()}_{file.name}"

                # Upload to Supabase
                supabase.storage.from_("uploads").upload(
                    path=file_path,
                    file=file_data,
                    file_options={"content-type": file.content_type}
                )

                # Get public URL
                file_url = supabase.storage.from_("uploads").get_public_url(file_path)

                # Save file metadata to the database
                UploadedFile.objects.create(
                    title=file_title,
                    file_url=file_url,
                    user=user
                )

                success = "File uploaded successfully!"
            except Exception as e:
                error = f"Supabase upload failed: {e}"

        else:
            error = "Invalid form data."

    else:
        form = UploadFileForm()

    # File filtering
    if filter_type == 'all':
        files = UploadedFile.objects.all()
    else:
        files = UploadedFile.objects.filter(user__email=user_email)

    return render(request, 'dashboard.html', {
        'files': files,
        'filter_type': filter_type,
        'form': form,
        'success': success,
        'error': error,
    })

# Upload file function
def handle_uploaded_file(request):
    if request.method == "POST" and request.FILES.get("file"):
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES["file"]
            title = form.cleaned_data["title"]
            user = request.user

            # Generate unique file path and name
            folder_name = f"user-{user.id}"
            file_name = f"{uuid.uuid4()}_{file.name}"
            file_path = f"{folder_name}/{file_name}"

            try:
                # Upload file to Supabase
                supabase.storage.from_('your-bucket-name').upload(file_path, file, {"content-type": file.content_type})

                # Get the public URL
                public_url = supabase.storage.from_('your-bucket-name').get_public_url(file_path)

                # Save file metadata in the UploadedFile model
                UploadedFile.objects.create(
                    user=user,
                    title=title,
                    public_url=public_url,
                    path_in_bucket=file_path  # Store the actual path in the bucket
                )

                return render(request, "upload.html", {
                    "form": UploadFileForm(),
                    "success": "File uploaded successfully!"
                })

            except Exception as e:
                return render(request, "upload.html", {
                    "form": form,
                    "error": f"Supabase upload failed: {e}"
                })

    else:
        form = UploadFileForm()

    return render(request, "upload.html", {"form": form})


def upload(request):
    if request.method == "POST" and request.FILES.get("file"):
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES["file"]
            file_title = form.cleaned_data["title"]
            user = request.user

            # Upload file to Supabase
            try:
                file_data = file.read()
                file_path = f"{user.id}/{datetime.now().timestamp()}_{file.name}"

                supabase.storage.from_("uploads").upload(
                    path=file_path,
                    file=file_data,
                    file_options={"content-type": file.content_type}
                )

                # Get public URL
                file_url = supabase.storage.from_("uploads").get_public_url(file_path)

                UploadedFile.objects.create(
                    title=file_title,
                    file_url=file_url,
                    user=user
                )

                return render(request, "upload.html", {
                    "form": UploadFileForm(),
                    "success": "File uploaded successfully!",
                })
            except Exception as e:
                return render(request, "upload.html", {
                    "form": form,
                    "error": f"Supabase upload failed: {e}"
                })

    else:
        form = UploadFileForm()

    return render(request, "upload.html", {"form": form})

def delete_file(request, file_id):
    if request.method == 'POST':
        try:
            file = get_object_or_404(UploadedFile, id=file_id)
            file.delete()  # Ensure to remove from storage as well if needed
            return redirect('dashboard')
        except UploadedFile.DoesNotExist:
            return redirect('dashboard')  # If file doesn't exist, just redirect to dashboard

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


def redirect_if_logged_in(request):
    if request.session.get('user_email'):
        return redirect('dashboard')

from supabase import create_client
import time


def download_file(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)

    # Get path of the file in the bucket (e.g., "myfiles/report.pdf")
    file_path = uploaded_file.path_in_bucket  # ensure you store this when uploading

    # Generate signed URL (valid for 60 seconds)
    response = supabase.storage.from_('uploads').create_signed_url(file_path, 60)
    signed_url = response.get("signedURL")

    if signed_url:
        return redirect(signed_url)
    else:
        return HttpResponse("Failed to generate download link", status=400)



