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
# from polls.models_chats import *
# from polls.models_requests_and_friends import *
# from polls.models_profile import *

class Notification(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE,null=True)
    friends_last_time = models.DateTimeField(default=timezone.now)
    request_flag = models.BooleanField(default=False)
    # chat_object = models.ForeignKey(DmThrough, on_delete=models.CASCADE, null=True)
    chat_last_time = models.DateTimeField(default=timezone.now)
    chat_flag = models.BooleanField(default=False)
    comments_last_time = models.DateTimeField(default=timezone.now)
    comment_flag = models.BooleanField(default=False)
    def save_request_time(self):
        self.friends_last_time = timezone.now()
        self.save()
    def save_chat_time(self):
        self.chat_last_time = timezone.now()
        self.save()
    def save_comment_time(self):
        self.comments_last_time = timezone.now()
        self.save()
   