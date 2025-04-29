from django.contrib import admin

# Register your models here.
from .models import User_Data,UploadedFile,CustomUser
# Register your models here.
admin.site.register(User_Data)
admin.site.register(UploadedFile)
admin.site.register(CustomUser)