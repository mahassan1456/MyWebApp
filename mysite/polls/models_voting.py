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
    

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)
    users = models.ManyToManyField(settings.AUTH_USER_MODEL)
    

    def __str__(self) -> str:
        return self.choice_text
    def make_chart(self, request, question_id):
        labels =[]
        data = []
        qset = Choice.objects.filter(question= question_id)
        for dat in qset:
            labels.append(dat.choice_text)
            data.append(dat.votes)
        print(list(zip(labels,data)))
        

        return render(request, 'polls/chart.html', {
        'labels': labels,
        'data': data,
    })