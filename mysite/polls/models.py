from atexit import register
from datetime import datetime
from distutils.command.upload import upload
from email.policy import default

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
from polls.models_voting import *
    

class Image(models.Model):
    name = models.CharField(max_length=20,null=True)
    image = models.ImageField(upload_to='test/', null=True)

class Profile(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=30, blank=True)
    birthdate = models.DateField(null=True)
    picture = models.ImageField(upload_to='uploads/', null=True, verbose_name="", blank=True)
    canView = models.CharField(max_length=3, default='No')

    def resize(self):
        try:
            img = IMG.open(self.picture.path)
        except:
            return
        else:
            if img.height > 100 or img.width > 100:
                max_size=(100,100)                                                                                                                                                                                                                             
                img.thumbnail(max_size)                                                                                                                                                                                                                        
                img.save(self.picture.path)

    def save(self,*args,**kwargs):
        super().save(*args,**kwargs)
        self.resize()
        
        
class Notification(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE,null=True)
    friends_last_time = models.DateTimeField(default=timezone.now)
    request_flag = models.BooleanField(default=False)
    chat_last_time = models.DateTimeField(default=timezone.now)
    chat_flag = models.BooleanField(default=False)
    comments_last_time = models.DateTimeField(default=timezone.now)
    comment_flag = models.BooleanField(default=False)
    # stop_script = models.BooleanField(default=False)
    def save_request_time(self):
        self.friends_last_time = timezone.now()
        self.save()
    def save_chat_time(self):
        self.chat_last_time = timezone.now()
        self.save()
    def save_comment_time(self):
        self.comments_last_time = timezone.now()
        self.save()
   

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
        Circle.objects.create(user=instance)
        Notification.objects.create(user=instance)
        
@receiver(post_save, sender=User)
def save_user_profile(sender,instance,**kwargs):
    instance.profile.save()
    instance.user.save()
    instance.notification.save()


@receiver(post_save, sender=Question)
def pp(sender, **kwargs):
    print('Question Created')
    for it in kwargs:
        print(it,'-',kwargs[it])
    

from polls.models_chats import *
from polls.models_requests_and_friends import *
from polls.models_profile import *
from polls.models_voting import *

  