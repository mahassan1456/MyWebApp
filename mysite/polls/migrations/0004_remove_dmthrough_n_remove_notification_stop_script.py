# Generated by Django 4.0.7 on 2022-10-02 14:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('polls', '0003_notification_stop_script'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='dmthrough',
            name='n',
        ),
        migrations.RemoveField(
            model_name='notification',
            name='stop_script',
        ),
    ]
