# Generated by Django 5.1.2 on 2024-11-06 10:48

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_otp_expires_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expires_At',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 6, 10, 53, 34, 91857, tzinfo=datetime.timezone.utc)),
        ),
    ]