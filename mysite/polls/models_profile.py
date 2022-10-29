from atexit import register
from datetime import datetime
from distutils.command.upload import upload

from django.db import models
from django.utils import timezone
import datetime
from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save
from django.shortcuts import render
from PIL import Image as IMG
from django import template
from polls.models import Notification


class Comments(models.Model):
    user_c = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    notify = models.ForeignKey(Notification,on_delete=models.CASCADE,null=True)
    post_date = models.DateTimeField(auto_now_add=True)
    comment = models.TextField(max_length=500)
    posted_by = models.TextField(max_length=50, null=True)

    def make_comment(self, user_id):
        user = User.objects.get(pk=user_id)
        if self not in Comments.objects.all():
            user.comments_set.add(self)
            user.save()