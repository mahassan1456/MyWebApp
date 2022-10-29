from django.db import models
from django.conf import settings
from django.urls import reverse


# Create your models here.


class Tags(models.Model):
    tag = models.CharField(max_length=20)


class Article(models.Model):
    title = models.CharField(max_length=200, db_index=True)
    slug = models.SlugField(max_length=200, db_index=True, null=True)
    image = models.ImageField(upload_to='articles/', null=True, blank=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    extra = models.CharField(max_length=30,null=True,blank=True)
    tags = models.ManyToManyField(Tags, blank=True)

    # def get_absolute_url(self):
    #     return reverse('blog:all_posts')


    
    def __str__(self) -> str:
        return self.title
    class Meta:
        ordering = ['-created']

class Reply(models.Model):
    article = models.ForeignKey(Article, on_delete=models.CASCADE)
    content = models.TextField()
    madeby = models.CharField(max_length=50)
    created = models.DateTimeField(auto_now=True)
