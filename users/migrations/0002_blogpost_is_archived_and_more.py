# Generated by Django 5.1.2 on 2024-11-12 06:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='blogpost',
            name='is_archived',
            field=models.BooleanField(default=True),
        ),
        migrations.AddIndex(
            model_name='blogpost',
            index=models.Index(fields=['title'], name='users_blogp_title_6329ef_idx'),
        ),
    ]
