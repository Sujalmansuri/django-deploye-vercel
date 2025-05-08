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

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
# Dashboard View 
def dashboard(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            file_name = file.name
            user_email = request.session.get('user_email')
            
            try:
                user = User_Data.objects.get(email=user_email)
            except User_Data.DoesNotExist:
                messages.error(request, "User not found.")
                return redirect('dashboard')

            # Convert file to bytes and upload to Supabase
            try:
                file_bytes = file.read()
                bucket = supabase.storage.from_("uploads")  # Ensure 'uploads' bucket exists

                # Upload the file
                upload_res = bucket.upload(file_name, file_bytes)
                if upload_res.get("error"):
                    messages.error(request, f"Upload failed: {upload_res.get('error').get('message')}")
                    return redirect('dashboard')

                # Get the public URL for the file
                file_url = bucket.get_public_url(file_name).get('publicURL')

                # Save file info in DB
                UploadedFile.objects.create(
                    title=form.cleaned_data['title'],
                    file_url=file_url,
                    user=user,
                    path_in_bucket=file_name  # Save the file path in the bucket
                )

                messages.success(request, "File uploaded successfully.")
                return redirect('dashboard')
            except Exception as e:
                messages.error(request, f"Error uploading file: {str(e)}")
                return redirect('dashboard')

    else:
        form = UploadFileForm()

    query = request.GET.get('q')
    files = UploadedFile.objects.filter(title__icontains=query) if query else UploadedFile.objects.all()

    return render(request, 'dashboard.html', {
        'form': form,
        'files': files,
        'query': query or '',
        'user_email': request.session.get('user_email')
    })


def upload(request):
    if request.method == 'POST':
        # Retrieve form data
        title = request.POST['title']
        file = request.FILES['file']
        user_email = request.session.get('user_email')  # Make sure the session contains user_email
        try:
            user = User_Data.objects.get(email=user_email)  # Get the user object
        except User_Data.DoesNotExist:
            messages.error(request, "User does not exist.")
            return redirect('dashboard')

        # Convert file to bytes and upload to Supabase
        try:
            file_bytes = file.read()
            bucket = supabase.storage.from_("uploads")  # Ensure 'uploads' bucket exists
            file_name = file.name

            # Upload the file
            upload_res = bucket.upload(file_name, file_bytes)
            if upload_res.get("error"):
                messages.error(request, f"Upload failed: {upload_res.get('error').get('message')}")
                return redirect('dashboard')

            # Get the public URL for the file
            file_url = bucket.get_public_url(file_name).get('publicURL')

            # Store the file URL or other relevant details in the database
            UploadedFile.objects.create(
                title=title,
                file_url=file_url,
                user=user
            )
            messages.success(request, "File uploaded successfully.")
            return redirect('dashboard')

        except Exception as e:
            messages.error(request, f"Error uploading file: {str(e)}")
            return redirect('dashboard')

    return render(request, "upload.html")

def delete_file(request, pk):
    file = UploadedFile.objects.get(pk=pk)
    supabase_bucket = "uploads"
    delete_url = f"{SUPABASE_URL}/storage/v1/object/{supabase_bucket}/{file.path_in_bucket}"

    headers = {
        "apikey":SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
    }

    response = requests.delete(delete_url, headers=headers)

    if response.status_code in [200, 204]:
        file.delete()
        messages.success(request, "File deleted successfully.")
    else:
        messages.error(request, "File deletion from Supabase failed.")

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

    # Get path of the file in the bucket (e.g., "myfiles/report.pdf")
    file_path = uploaded_file.path_in_bucket  # ensure you store this when uploading

    # Generate signed URL (valid for 60 seconds)
    response = supabase.storage.from_('uploads').create_signed_url(file_path, 60)
    signed_url = response.get("signedURL")

    if signed_url:
        return redirect(signed_url)
    else:
        return HttpResponse("Failed to generate download link", status=400)





