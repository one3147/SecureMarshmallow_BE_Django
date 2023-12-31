# Generated by Django 4.0.2 on 2023-05-25 22:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Marshmallow', '0012_imagedata_alter_image_create_at'),
    ]

    operations = [
        migrations.CreateModel(
            name='article',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField()),
                ('created_by', models.CharField(max_length=100)),
                ('modified_at', models.DateTimeField()),
                ('modified_by', models.CharField(max_length=100)),
                ('content', models.CharField(max_length=10000)),
                ('hashtag', models.CharField(max_length=255, null=True)),
                ('title', models.CharField(max_length=255)),
            ],
        ),
        migrations.DeleteModel(
            name='Board',
        ),
    ]
