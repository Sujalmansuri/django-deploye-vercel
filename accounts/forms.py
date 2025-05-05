
from .models import UploadedFile

class  UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['title', 'file']
