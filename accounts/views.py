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

# Load environment variables
load_dotenv()

# Supabase initialization
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_API_KEY)

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

# Dashboard - Lists uploaded files
def dashboard(request):
    if 'user_email' not in request.session:
        return redirect('login')

    user_email = request.session['user_email']
    filter_type = request.GET.get('filter', 'myfiles')

    if filter_type == 'all':
        files = UploadedFile.objects.all()
    else:
        files = UploadedFile.objects.filter(user__email=user_email)

    return render(request, 'dashboard.html', {
        'files': files,
        'filter_type': filter_type,
    })

# File Upload Helper
def handle_uploaded_file(f):
    file_name = f.name
    file_content = f.read()
    result = supabase.storage.from_('uploads').upload(file_name, file_content, {"content-type": f.content_type})
    
    if result.get("error"):
        raise Exception("Upload failed: " + str(result["error"]))

    return f"uploads/{file_name}"

# File Upload View
def upload(request):
    if request.method == "POST" and request.FILES["file"]:
        uploaded_file = request.FILES["file"]
        title = request.POST.get("title")

        file_instance = UploadedFile(title=title, file=uploaded_file, user=request.user)
        file_instance.save()

        return redirect('dashboard')

    return render(request, "upload.html")

# Download File
def download_file(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.get(pk=file_id)
        file_url = uploaded_file.file_url
        return HttpResponse(f"File URL: {file_url}")
    except UploadedFile.DoesNotExist:
        raise Http404("File not found")

# Delete File
def delete_file(request, file_id):
    if request.method == 'POST':
        file = get_object_or_404(UploadedFile, id=file_id)
        file.delete()  # Also remove from Supabase if applicable
    return redirect('dashboard')

# Signup Submit
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
            password=make_password(password),
            is_google_user=False
        )

        request.session['user_email'] = user.email
        request.session['user_name'] = user.full_name

        return redirect('dashboard')

    return redirect('signup_page')

# Email/Password Login
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User_Data.objects.get(email=email)

            if user.password and check_password(password, user.password):
                request.session['user_email'] = user.email
                request.session['user_name'] = user.full_name
                return redirect('dashboard')

            return render(request, 'login.html', {'error': 'Invalid credentials!'})

        except User_Data.DoesNotExist:
            return render(request, 'login.html', {'error': 'User does not exist!'})

    return redirect('login_page')

# Google Login
def google_login(request):
    flow = Flow.from_client_config(
        client_config=settings.GOOGLE_CREDENTIALS,
        scopes=[
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid'
        ],
        redirect_uri="https://yourdomain.com/complete/google/"
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
        redirect_uri="https://yourdomain.com/complete/google/"
    )
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials
    try:
        id_info = id_token.verify_oauth2_token(credentials.id_token, google_requests.Request())
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

# Logout
def logout_view(request):
    request.session.flush()
    return redirect('/')


# Login Submit
def login_submit(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User_Data.objects.get(email=email)  # 🔴 FIXED: changed User to User_Data

            if check_password(password, user.password):
                request.session['user_email'] = user.email
                request.session['user_name'] = user.full_name
                return redirect('dashboard')
            else:
                return render(request, 'login.html', {'error': 'Invalid credentials'})

        except User_Data.DoesNotExist:
            return render(request, 'login.html', {'error': 'User does not exist'})

    return redirect('login_page')
