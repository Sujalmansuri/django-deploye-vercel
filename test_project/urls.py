from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from accounts import views  # Import views from accounts app

urlpatterns = [
    path('', views.home, name='home_page'),
    path('login/', views.login_page, name='login_page'),
    path('login/submit/', views.login_submit, name='login_view'), 
    path('signup/', views.signup_page, name='signup_page'),
    path('signup/submit/', views.signup_submit, name='signup_submit'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload, name='upload'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    

    # Google OAuth Routes
    path('google/login/', views.google_login, name='google_login'),
    path('complete/google/', views.google_callback, name='google_callback'),

    # Email/Password Login Handler
    path('login-handler/', views.login_view, name='login'),

    # File Download
    path('download/<int:file_id>/', views.download_file, name='download_file'),
]

# Serving media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
