# Generated by Django 4.0.2 on 2023-06-14 23:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Marshmallow', '0017_marshmallow_user_refreshtoken'),
    ]

    operations = [
        migrations.AddField(
            model_name='image',
            name='hashtag',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
