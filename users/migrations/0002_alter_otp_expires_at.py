# Generated by Django 5.1.2 on 2024-11-06 08:20

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expires_At',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 6, 8, 25, 34, 553297, tzinfo=datetime.timezone.utc)),
        ),
    ]
