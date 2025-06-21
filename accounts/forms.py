from django import forms

class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=255, label="File Title")
    file = forms.FileField(label="Select File")
    notify_emails = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'example1@gmail.com, example2@gmail.com'}),
        label="Notify Emails (comma-separated)"
    )