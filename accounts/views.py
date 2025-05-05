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


# def dashboard(request):
#     filter_type = request.GET.get('filter', 'myfiles')
#     user = request.user
    
#     success = error = None

#     # Handle file upload
#     if request.method == 'POST' and request.FILES.get('file'):
#         form = UploadFileForm(request.POST, request.FILES)
#         if form.is_valid():
#             uploaded_file = form.save(commit=False)
#             uploaded_file.user = user
#             uploaded_file.save()
#             success = "File uploaded successfully!"
#         else:
#             error = "Error uploading file."
#     else:
#         form = UploadFileForm()

#     # Filter files
#     if filter_type == 'all':
#         files = UploadedFile.objects.all().order_by('-id')
#     else:
#         files = UploadedFile.objects.filter(user=user).order_by('-id')

#     return render(request, 'dashboard.html', {
#         'files': files,
#         'filter_type': filter_type,
#         #'form': form,
#         'success': success,
#         'error': error,
#     })


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
            uploaded_file = form.save(commit=False)
            uploaded_file.user = request.user  # or use your custom user if applicable
            uploaded_file.save()
            success = "File uploaded successfully!"
        else:
            error = "Error uploading file."
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
def handle_uploaded_file(f):
    # Save file to storage (Supabase Storage)
    file_name = f.name
    file_content = f.read()

    # Upload to Supabase Storage bucket named 'uploads'
    result = supabase.storage.from_('uploads').upload(file_name, file_content, {"content-type": f.content_type})

    if result.get("error"):
        raise Exception("Upload failed: " + str(result["error"]))

    # Return the path or public URL
    return f"uploads/{file_name}"

# def upload(request):
#     if request.method == "POST" and request.FILES.get("file"):
#         form = UploadFileForm(request.POST, request.FILES)
#         if form.is_valid():
#             file = request.FILES["file"]
#             file_title = form.cleaned_data["title"]
#             user = request.user

#             # Upload file to Supabase
#             try:
#                 file_data = file.read()
#                 file_path = f"{user.id}/{datetime.now().timestamp()}_{file.name}"

#                 supabase.storage.from_("uploads").upload(
#                     path=file_path,
#                     file=file_data,
#                     file_options={"content-type": file.content_type}
#                 )

#                 # Get public URL
#                 file_url = supabase.storage.from_("uploads").get_public_url(file_path)

#                 UploadedFile.objects.create(
#                     title=file_title,
#                     file_url=file_url,
#                     user=user
#                 )

#                 return render(request, "upload.html", {
#                     "form": UploadFileForm(),
#                     "success": "File uploaded successfully!",
#                 })
#             except Exception as e:
#                 return render(request, "upload.html", {
#                     "form": form,
#                     "error": f"Supabase upload failed: {e}"
#                 })

#     else:
#         form = UploadFileForm()

#     return render(request, "upload.html", {"form": form})

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

def download_file(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.get(pk=file_id)
        file_url = uploaded_file.file_url
        return redirect(file_url)
    except UploadedFile.DoesNotExist:
        raise Http404("File not found")

