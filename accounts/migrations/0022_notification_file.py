# Generated by Django 4.2.7 on 2025-06-21 15:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0021_notification'),
    ]

    operations = [
        migrations.AddField(
            model_name='notification',
            name='file',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='accounts.uploadedfile'),
            preserve_default=False,
        ),
    ]
