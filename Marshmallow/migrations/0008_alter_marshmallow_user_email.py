# Generated by Django 4.0.3 on 2023-05-11 00:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Marshmallow', '0007_rename_username_board_id_remove_image_username_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='marshmallow_user',
            name='email',
            field=models.EmailField(max_length=320),
        ),
    ]
