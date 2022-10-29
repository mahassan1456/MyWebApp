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




######################## PARENT CHAT OBJECT CHAT MESSAGES #################
class DmThrough(models.Model):
    id = models.CharField(max_length=10,primary_key=True)
    who_last_u = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    notification = models.ForeignKey(Notification,on_delete=models.CASCADE,null=True)
    last_updated = models.DateTimeField(auto_now=True)
    new_messages = models.BooleanField()
    who_last = models.CharField(max_length=40, null=True) 
    
 
    def create_key(self, id, id1):
        self.id = str(id) + '-' + str(id1) if id < id1 else str(id1) + '-' + str(id)
        super().save()


class DM(models.Model):
    comp = models.ForeignKey(DmThrough, on_delete=models.CASCADE, related_name='dm_set', null=True)
    mb = models.ForeignKey(User, on_delete=models.CASCADE, null=True, related_name='mb')
    fw = models.ForeignKey(User, on_delete=models.CASCADE, null=True, related_name='fw')
    message = models.CharField(max_length=200)
    created = models.DateTimeField(auto_now_add=True)
    usermade = models.CharField(max_length=45, null=True)
    

    def save(self):
        if not self.comp:
            # self.comp = str(self.mb.id) + '-' + str(self.fw.id)
            self.comp = str(self.mb.id) + '-' + str(self.fw.id) if self.mb.id < self.fw.id else str(self.fw.id) + '-' + str(self.mb.id)  
        super().save()

    class Meta:
        ordering = ["-created"]