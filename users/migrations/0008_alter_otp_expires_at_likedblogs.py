# Generated by Django 5.1.2 on 2024-11-08 10:59

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_alter_otp_expires_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expires_At',
            field=models.DateTimeField(),
        ),
        migrations.CreateModel(
            name='LikedBlogs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('blogpost', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.blogpost')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('user', 'blogpost'), name='unique_user_blogpost_like')],
            },
        ),
    ]
