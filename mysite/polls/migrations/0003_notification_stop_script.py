# Generated by Django 4.0.7 on 2022-10-02 06:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('polls', '0002_dmthrough_n'),
    ]

    operations = [
        migrations.AddField(
            model_name='notification',
            name='stop_script',
            field=models.BooleanField(default=False),
        ),
    ]
