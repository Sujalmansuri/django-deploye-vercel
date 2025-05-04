
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from .models import User_Data,CustomUser
from .models import UploadedFile  # ✅ Instead of File
from .forms import FileUploadForm  # ✅ Now this will work
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
from django.urls import reverse
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
from django.http import JsonResponse
from supabase import create_client
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables fr
# om .env file
load_dotenv()

# Now you can access your variables from the environment
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_API_KEY)



# Ensure OAuth works in dev environment
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Redirect if already logged in
def redirect_if_logged_in(request):
    print("Session Data:", request.session.items())
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
@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


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

# Your Django view
import os
from datetime import datetime
from django.http import JsonResponse
from supabase import create_client
from django.conf import settings

SUPABASE_URL = os.getenv('SUPABASE_URL')  # e.g., https://xyzcompany.supabase.co
SUPABASE_API_KEY = os.getenv('SUPABASE_API_KEY') 
# Initialize Supabase client
supabase = create_client(SUPABASE_URL,SUPABASE_API_KEY)

def upload(request):
    if request.method == "POST":
        uploaded_file = request.FILES["file"]  # file input name="file"
        
        # Upload file to 'uploads' bucket
        file_data = uploaded_file.read()
        file_path = f"{uploaded_file.name}"

        response = supabase.storage.from_("uploads").upload(file_path, file_data, {
            "content-type": uploaded_file.content_type,
            "upsert": True
        })

        # Get public URL
        public_url = supabase.storage.from_("uploads").get_public_url(file_path)

        return HttpResponse(f"Uploaded successfully! Public URL: <a href='{public_url}'>{public_url}</a>")

    return render(request, "upload.html")


# Upload view - Handling file uploads to Supabase
def upload(request):
    if request.method == 'POST':
        title = request.POST['title']
        file = request.FILES['file']
        user_email = request.session.get('user_email')
        user = User_Data.objects.get(email=user_email)

        uploaded_file = UploadedFile(title=title, user=user)
        uploaded_file.save()

        # Upload the file to Supabase
        uploaded_file.upload_to_supabase(file)

        return redirect('dashboard')

# Download File
from django.http import FileResponse, Http404
def download_file(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.get(pk=file_id)
        file_path = uploaded_file.file.path
        return FileResponse(open(file_path, 'rb'), as_attachment=True)
    except UploadedFile.DoesNotExist:
        raise Http404("File not found")

from django.shortcuts import render
from .models import UploadedFile


# Logout View
def logout_view(request):
    request.session.flush()
    return redirect('/')  # Ensure 'home' is named properly in urls.py


    
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
        redirect_uri = "https://instadatacom.vercel.app/complete/google/",
        #https://instadatacom.vercel.app/complete/google/
 # 🔴 CHANGED
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
        redirect_uri="https://instadatacom.vercel.app/complete/google/" 
 # 🔴 CHANGED
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

    return redirect('dashboard')  # 🔴 FIXED: redirect to dashboard after Google login



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

def github_login(request):
    """
    Redirect to GitHub's OAuth authorization page
    """
    client_id = settings.GITHUB_CLIENT_ID
    redirect_uri = 'http://127.0.0.1:8000/github/callback/'  # The callback URL
    github_auth_url = f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=user:email"
    return redirect(github_auth_url)

def github_callback(request):
    """
    Handle GitHub's OAuth callback and authenticate the user
    """
    code = request.GET.get('code')  # Get the code from the URL parameters
    if not code:
        return JsonResponse({'error': 'No code provided'}, status=400)

    # Step 1: Exchange code for access token
    token_url = 'https://github.com/login/oauth/access_token'
    headers = {'Accept': 'application/json'}
    data = {
        'client_id': settings.GITHUB_CLIENT_ID,
        'client_secret': settings.GITHUB_CLIENT_SECRET,
        'code': code
    }
    token_response = requests.post(token_url, headers=headers, data=data)
    access_token = token_response.json().get('access_token')

    if not access_token:
        return JsonResponse({'error': 'Failed to get access token'}, status=400)

    # Step 2: Use the access token to fetch user information
    user_info_url = 'https://api.github.com/user'
    email_url = 'https://api.github.com/user/emails'
    headers = {'Authorization': f'token {access_token}'}

    user_info = requests.get(user_info_url, headers=headers).json()
    user_emails = requests.get(email_url, headers=headers).json()

    primary_email = None
    for email in user_emails:
        if email.get('primary'):
            primary_email = email.get('email')
            break

    if not primary_email:
        return JsonResponse({'error': 'Email not found'}, status=400)

    # Step 3: Create or get the user from the database
    user, created = CustomUser.objects.get_or_create(email=primary_email)
    if created:
        user.name = user_info.get('name') or user_info.get('login')
        user.save()

    # Step 4: Log the user in (custom login logic)
    request.session['user_id'] = user.id
    request.session['user_email'] = user.email

    # Redirect to the dashboard or any authenticated view
    return redirect('dashboard')  # Adjust according to your app's URL configuration
def logout_view(request):
    # Clear the session
    request.session.flush()
    return redirect('/')  # Redirect to homepage after logout
