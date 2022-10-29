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
from mysite.polls.models_chats import *
from mysite.polls.models_requests_and_friends import *
from mysite.polls.models_profile import *
from mysite.polls.models_voting import *




# Create your models here.

# User


# class Comments(models.Model):
#     user_c = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
#     notify = models.ForeignKey(Notification)
#     post_date = models.DateTimeField(auto_now_add=True)
#     comment = models.TextField(max_length=500)
#     posted_by = models.TextField(max_length=50, null=True)

#     def make_comment(self, user_id):
#         user = User.objects.get(pk=user_id)
#         if self not in Comments.objects.all():
#             user.comments_set.add(self)
#             user.save()

        
        

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

    def rs(self):
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
        self.rs()
        
        
class Notification(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE,null=True)
    friends_last_time = models.DateTimeField(default=timezone.now)
    request_flag = models.BooleanField(default=False)
    chat_object = models.ForeignKey(DmThrough, on_delete=models.CASCADE, null=True)
    chat_last_time = models.DateTimeField(default=timezone.now)
    chat_flag = models.BooleanField(default=False)
    comments_last_time = models.DateTimeField(default=timezone.now)
    comment_flag = models.BooleanField(default=False)
    def save_request_time(self):
        self.friends_last_time = datetime.now()
        self.save()
    def save_chat_time(self):
        self.chat_last_time = datetime.now()
        self.save()
    def save_comment_time(self):
        self.comments_last_time = datetime.now()
        self.save()

# ERROR NAME self.RelatedObjectDoesNotExist
# class Comments(models.Model):
    # user_c = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    # notify = models.ForeignKey(Notification,on_delete=models.CASCADE,null=True)
    # post_date = models.DateTimeField(auto_now_add=True)
    # comment = models.TextField(max_length=500)
    # posted_by = models.TextField(max_length=50, null=True)

    # def make_comment(self, user_id):
    #     user = User.objects.get(pk=user_id)
    #     if self not in Comments.objects.all():
    #         user.comments_set.add(self)
    #         user.save()



    # def save(self,*args,**kwargs):
    #     super().save(*args,**kwargs)
    #     from PIL import Image
    #     img = Image.open(self.profile.path)

    #     if img.height > 100 or img.width > 100:
    #         max_size=(100,100)                                                                                                                                                                                                                             
    #         img.thumbnail(max_size)                                                                                                                                                                                                                        
    #         img.save(self.image.path)

# class Circle(models.Model):
#     user = models.OneToOneField(User, primary_key=True, on_delete=models.CASCADE, related_name='user')
#     friends = models.ManyToManyField(User, related_name='friends')
#     requests = models.ManyToManyField(User, related_name='requests')
#     sent_requests = models.ManyToManyField(User, related_name='sent_requests')
#     chats = models.ManyToManyField(User,related_name='chats',null=True)
#     to_notify = models.BooleanField(default=False)

#     def unrequest(self, user_id):
#         account = User.objects.get(pk=user_id)
#         self.sent_requests.remove(account)
#         account.user.requests.remove(self.user)
#         self.save()
#         account.save()

#     def accept(self, account):
#         account = User.objects.get(pk=account)
#         if account in self.requests.all():
#             self.requests.remove(account)
#             account.user.sent_requests.remove(self.user)
#             if account not in self.friends.all():
#                 self.friends.add(account)
#                 account.user.friends.add(self.user)
#                 self.save()
#                 account.user.save()
                
#     def remove_friend(self,account):
#         account = User.objects.get(pk=account)
#         if account in self.friends.all():
#             self.friends.remove(account)
#             account.user.friends.remove(self.user)
#             self.save()
#             account.user.save()

#     def send_request(self,account):
#         friender = User.objects.get(pk=account)
#         if friender not in self.sent_requests.all():
#             friender.user.requests.add(self.user)
#             # friender.save()
#             self.sent_requests.add(friender)
#         # self.save()
#     def is_mutual(self):
#         mf = []
#         for friends in self.friends.all():
#             for friend in friends.user.friends.all():
#                 if friend not in self.friends.all() and friend != self.user:
#                     mf.append((friends, friend))
#         return mf

# @receiver(pre_save, sender=User)   
# def resize(sender,instance,created, **kwargs):


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



class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('Date Published')
    user_p = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE, null=True
    )

    def was_published_recently(self):
        return self.pub_date >= timezone.now() - datetime.timedelta(days=1)
    
    def deleteChoices(self,new_question_text,choice_list):
        self.choice_set.all().delete()
        self.save()
        self.question_text = new_question_text
        self.save()
        choice_list = [x.strip() for x in choice_list.split('\n')]
        for choice in choice_list:
            if choice:
                self.choice_set.create(choice_text=choice, votes=0)
                self.save()
    def c_name(self):
        return Question.__class__.__name__

    def __str__(self):
        return self.question_text

@receiver(post_save, sender=Question)
def pp(sender, **kwargs):
    print('Question Created')
    for it in kwargs:
        print(it,'-',kwargs[it])
    

# class Choice(models.Model):
#     question = models.ForeignKey(Question, on_delete=models.CASCADE)
#     choice_text = models.CharField(max_length=200)
#     votes = models.IntegerField(default=0)
#     users = models.ManyToManyField(settings.AUTH_USER_MODEL)
    

#     def __str__(self) -> str:
#         return self.choice_text
    # def make_chart(self, request, question_id):
    #     labels =[]
    #     data = []
    #     qset = Choice.objects.filter(question= question_id)
    #     for dat in qset:
    #         labels.append(dat.choice_text)
    #         data.append(dat.votes)
    #     print(list(zip(labels,data)))
        

    #     return render(request, 'polls/chart.html', {
    #     'labels': labels,
    #     'data': data,
    # })


# class Userchoice(models.Model):
#     pass
# class DmThrough(models.Model):
#     id = models.CharField(max_length=10,primary_key=True)
#     last_updated = models.DateTimeField(auto_now=True)
#     new_messages = models.BooleanField()
#     who_last = models.CharField(max_length=40, null=True)
#     who_last_u = models.ForeignKey(User, on_delete=models.CASCADE, null=True)

#     def create_key(self, id, id1):
#         self.id = str(id) + '-' + str(id1) if id < id1 else str(id1) + '-' + str(id)
#         super().save()

# class DM(models.Model):
#     comp = models.ForeignKey(DmThrough, on_delete=models.CASCADE, related_name='dm_set', null=True)
#     mb = models.ForeignKey(User, on_delete=models.CASCADE, null=True, related_name='mb')
#     fw = models.ForeignKey(User, on_delete=models.CASCADE, null=True, related_name='fw')
#     message = models.CharField(max_length=200)
#     created = models.DateTimeField(auto_now_add=True)
#     usermade = models.CharField(max_length=45, null=True)
    

#     def save(self):
#         if not self.comp:
#             # self.comp = str(self.mb.id) + '-' + str(self.fw.id)
#             self.comp = str(self.mb.id) + '-' + str(self.fw.id) if self.mb.id < self.fw.id else str(self.fw.id) + '-' + str(self.mb.id)  
#         super().save()

#     class Meta:
#         ordering = ["-created"]

# class Notification(models.Model):
#     user = models.OneToOneField(User,on_delete=models.CASCADE,null=True)
#     friends_last_time = models.DateTimeField(default=timezone.now)
    # request_flag = models.BooleanField(default=False)
    # chat_object = models.ForeignKey(DmThrough, on_delete=models.CASCADE, null=True)
    # chat_last_time = models.DateTimeField(default=timezone.now)
    # chat_flag = models.BooleanField(default=False)
    # comments_last_time = models.DateTimeField(default=timezone.now)
    # comment_flag = models.BooleanField(default=False)
    # def save_request_time(self):
    #     self.friends_last_time = datetime.now()
    #     self.save()
    # def save_chat_time(self):
    #     self.chat_last_time = datetime.now()
    #     self.save()
    # def save_comment_time(self):
    #     self.comments_last_time = datetime.now()
    #     self.save()


# class DM(models.Model):
#     people = models.ManyToManyField(User)
#     message = models.CharField(max_length=100)
#     created = models.DateTimeField(auto_now_add=True)

# class Bread(models.Model):
#     name = models.CharField(max_length=35)
 
# class Cheese(models.Model):
#     type = models.CharField(max_length=30, unique=True)
#     breads = models.ManyToManyField(Bread, through='BreadType') 

# class BreadType(models.Model):
#     bread = models.ForeignKey(Bread, on_delete=models.CASCADE)
#     cheese = models.ForeignKey(Cheese, on_delete=models.CASCADE)
#     additional = models.CharField(max_length=30)

# class T(models.Model):
#     t1 = models.ForeignKey(Cheese, to_field='type', on_delete=models.CASCADE,null=True)
#     add = models.CharField(max_length=200)



  