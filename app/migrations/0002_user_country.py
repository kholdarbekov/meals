# Generated by Django 3.2.7 on 2021-09-07 11:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='country',
            field=models.CharField(default='UZB', max_length=3),
        ),
    ]
