# Generated by Django 4.0.2 on 2023-05-28 06:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Marshmallow', '0015_alter_article_modified_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='article',
            name='id',
            field=models.IntegerField(primary_key=True, serialize=False),
        ),
    ]
