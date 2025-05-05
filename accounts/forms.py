# forms.py
from django import forms
from .models import UploadedFile

class UploadFileForm(forms.ModelForm):
    file = forms.FileField(required=True)

    class Meta:
        model = UploadedFile
        fields = ['title', 'file']
