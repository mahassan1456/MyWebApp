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



class Circle(models.Model):
    user = models.OneToOneField(User, primary_key=True, on_delete=models.CASCADE, related_name='user')
    friends = models.ManyToManyField(User, related_name='friends')
    requests = models.ManyToManyField(User, related_name='requests')
    sent_requests = models.ManyToManyField(User, related_name='sent_requests')
    chats = models.ManyToManyField(User,related_name='chats',null=True)
    to_notify_friends = models.ManyToManyField(User,null=True)
    to_notify_time = models.DateTimeField(default=timezone.now,null=True)
    to_notify = models.BooleanField(default=False)

    def unrequest(self, user_id):
        account = User.objects.get(pk=user_id)
        self.sent_requests.remove(account)
        account.user.requests.remove(self.user)
        account.user.to_notify_friends.remove(self.user)
        account.user.save()
        self.save()
        account.save()
        if len(account.user.requests.all()) == 0:
            account.notification.request_flag = False
            
        

    def accept(self, account):
        account = User.objects.get(pk=account)
        if account in self.requests.all():
            self.requests.remove(account)
            account.user.sent_requests.remove(self.user)
            print("beforeeeeeee",len(self.requests.all()))
            if account not in self.friends.all():
                self.friends.add(account)
                self.to_notify_friends.remove(account)
                self.user.notification.friends_last_time = timezone.now()
                self.user.notification.save()
                account.user.friends.add(self.user)
                self.save()
                account.user.save()
                print("after",len(self.requests.all()))
                if len(self.requests.all()) == 0:
                    self.user.notification.request_flag = False
                    self.user.notification.save()
                
    def remove_friend(self,account):
        account = User.objects.get(pk=account)
        if account in self.friends.all():
            self.friends.remove(account)
            account.user.friends.remove(self.user)
            self.save()
            account.user.save()

    def send_request(self,account):
        friender = User.objects.get(pk=account)
        if friender not in self.sent_requests.all():
            friender.user.requests.add(self.user)
            friender.user.to_notify_time = timezone.now()
            friender.user.to_notify_friends.add(self.user)
            friender.user.save()
            # friender.save()
            self.sent_requests.add(friender)
            self.save()
            
        # self.save()
    def is_mutual(self):
        mf = []
        for friends in self.friends.all():
            for friend in friends.user.friends.all():
                if friend not in self.friends.all() and friend != self.user:
                    mf.append((friends, friend))
        return mf
    
