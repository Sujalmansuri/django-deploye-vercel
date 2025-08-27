from io import StringIO
import os

import requests
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from supabase import create_client

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate, login, logout
from .models import User_Data, UploadedFile
from .forms import UploadFileForm
from accounts import views

load_dotenv()

# Supabase config
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
SUPABASE_PROJECT_ID = os.getenv("SUPABASE_PROJECT_ID")
BUCKET_NAME = "uploads"
supabase = create_client(SUPABASE_URL, SUPABASE_API_KEY)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def redirect_if_logged_in(request):
    user_email = request.session.get('user_email')
    if user_email and User_Data.objects.filter(email=user_email).exists():
        return redirect('dashboard')
    return redirect('login')


def home(request):
    return render(request, 'Home.html')


def login_page(request):
    return render(request, 'login.html')


def signup_page(request):
    return render(request, 'signup.html')


from django.core.mail import send_mail
from .models import UploadedFile, User_Data, Notification
from .forms import UploadFileForm
from django.conf import settings
from django.core.mail import send_mass_mail
def upload_file(request):
    if request.method == 'POST':
        user_email = request.session.get('user_email')
        if not user_email:
            messages.info(request, "User not logged in.")
            return redirect('login')

        form = UploadFileForm(request.POST, request.FILES)
        if not form.is_valid():
            messages.info(request, "Invalid form submission.")
            return redirect('dashboard')

        file = request.FILES['file']
        title = request.POST.get('title') or file.name
        file_name = file.name
        supabase_bucket = "uploads"
        
        try:
            
            upload_response = supabase.storage.from_(supabase_bucket).upload(file_name, file.read())
            if getattr(upload_response, 'error', None):
                messages.info(request, f"Upload failed: {upload_response.error.message}")
                return redirect('dashboard')

            public_url = supabase.storage.from_(supabase_bucket).get_public_url(file_name)

           
            uploaded_file_instance = UploadedFile.objects.create(
                title=title,
                public_url=public_url,
                path_in_bucket=file_name,
                user_email=user_email,
            )
             # ✅ Check if file is CSV
            if file_name.endswith('.csv'):
                import pandas as pd
                # Read file content from the uploaded file (in memory)
                file.seek(0)  # Reset pointer
                csv_data = file.read().decode('utf-8')
                df = pd.read_csv(StringIO(csv_data))

                # Store summary in session for the next view
                request.session['csv_summary'] = {
                    "rows": df.shape[0],
                    "columns": df.shape[1],
                    "columns_list": list(df.columns),
                    "describe": df.describe().to_html(classes='table table-bordered'),
                }
                request.session['csv_file_name'] = file_name
                request.session['csv_preview'] = df.head(10).to_html(classes='table table-striped')

                return redirect('csv_analysis')

            
            notify_emails = request.POST.get('notify_emails', '')
            notify_email_list = [email.strip() for email in notify_emails.split(',') if email.strip()]

            notifications = []
            email_messages = []

            for email in notify_email_list:
                try:
                    user_obj = User_Data.objects.get(email=email)
                except User_Data.DoesNotExist:
                    continue  

               
                message = f"A new file titled '{title}' has been uploaded by {user_email}."
                notifications.append(Notification(
                    user=user_obj,
                    file=uploaded_file_instance,
                    message=message
                ))

                
                subject = f"New File Uploaded: {title}"
                email_body = (
                    f"Hello,\n\nA new file titled '{title}' has been uploaded by {user_email}.\n\n"
                    f"View/Download: {public_url}\n\n"
                    f"Regards,\nInstaData Team"
                )
                email_messages.append((subject, email_body, settings.DEFAULT_FROM_EMAIL, [email]))

            if notifications:
                Notification.objects.bulk_create(notifications)

            if email_messages:
                send_mass_mail(email_messages, fail_silently=True)

            messages.success(request, "File uploaded and notifications sent.")
            return redirect('dashboard')

        except Exception as e:
            messages.info(request, f"Upload error: {str(e)}")
            return redirect('dashboard')

    return redirect('dashboard')

def csv_analysis(request):
    csv_summary = request.session.get('csv_summary')
    csv_preview = request.session.get('csv_preview')
    file_name = request.session.get('csv_file_name')

    if not csv_summary:
        messages.error(request, "No CSV file data found.")
        return redirect('dashboard')

    return render(request, 'csv_analysis.html', {
        'summary': csv_summary,
        'preview': csv_preview,
        'file_name': file_name
    })

from .models import Notification

def dashboard(request):
    user_email = request.session.get('user_email')
    if not user_email:
        return redirect('home')

    user_name = request.session.get('user_name', 'Guest')

    query = request.GET.get('q', '')
    files = UploadedFile.objects.filter(title__icontains=query) if query else UploadedFile.objects.all()
    files = files.order_by('-uploaded_at')

    form = UploadFileForm()

    try:
        user= User_Data.objects.get(email=user_email)
        unread_notifications = Notification.objects.filter(user=user, is_read=False).order_by('-created_at')
        unread_count = unread_notifications.count()
    except User_Data.DoesNotExist:
        pass

    return render(request, 'dashboard.html', {
        'form': form,
        'files': files,
        'query': query,
        'user_email': user_email,
        'user_name': user_name,
        'unread_notifications': unread_notifications,
        'unread_notifications_count': unread_count,
    })
def delete_file(request, file_id):
    try:
        user_email = request.session.get('user_email')
        if not user_email:
            messages.info(request, "You must be logged in to delete files.")
            return redirect('login')

        file = get_object_or_404(UploadedFile, id=file_id)

        if file.user_email != user_email:
            messages.info(request, "Unauthorized: You can only delete your own files.")
            return redirect('dashboard')

        bucket = supabase.storage.from_("uploads")
        delete_response = bucket.remove([file.path_in_bucket])

        if isinstance(delete_response, list):
            file.delete()
            messages.success(request, "File deleted successfully.")
        else:
            messages.info(request, f"Failed to delete from Supabase: {delete_response}")

    except Exception as e:
        messages.info(request, f"Error deleting file: {str(e)}")

    return redirect('dashboard')


from .models import Notification
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from .models import UploadedFile, Notification, User_Data
import requests

from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from .models import UploadedFile, Notification, User_Data
import requests

def download_file(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)
    file_url = uploaded_file.public_url

    try:
        
        user_email = request.session.get('user_email')
        if user_email:
            try:
                user_obj = User_Data.objects.get(email=user_email)
                Notification.objects.filter(
                    user=user_obj,
                    file=uploaded_file,
                    is_read=False
                ).update(is_read=True)
            except User_Data.DoesNotExist:
                pass  

        
        response = requests.get(file_url, stream=True)
        response.raise_for_status()
        filename = uploaded_file.path_in_bucket

        django_response = HttpResponse(
            response.raw,
            content_type=response.headers.get('Content-Type', 'application/octet-stream')
        )
        django_response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return django_response

    except requests.RequestException:
        return HttpResponse("Error fetching file.", status=500)


def google_login(request):
    flow = Flow.from_client_config(
        client_config=settings.GOOGLE_CREDENTIALS,
        scopes=[
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid'
        ],
        redirect_uri="https://instadatacom.vercel.app/complete/google/"
    )
    authorization_url, state = flow.authorization_url()
    request.session['state'] = state
    return redirect(authorization_url)


def google_callback(request):
    flow = Flow.from_client_config(
        settings.GOOGLE_CREDENTIALS,
        scopes=[
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ],
        redirect_uri="https://instadatacom.vercel.app/complete/google/"
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


def logout_view(request):
    request.session.flush()
    return redirect('/')
