from re import template
from django.shortcuts import render
from django.views.generic import ListView, DetailView, CreateView, DeleteView
from django.shortcuts import get_object_or_404

from polls.views import success

from .models import Article, Reply
from .forms import ArticleForm
from django.http import HttpResponseRedirect
from django.urls import reverse
from PIL import Image
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin


# Create your views here.

class MakePost(LoginRequiredMixin, CreateView):
    template_name = 'blog/create.html'
    form_class = ArticleForm
    success_url = '/blog/'

    def form_valid(self,form):
        form.instance.author = self.request.user
        form.instance.slug = '-'.join(form.instance.title.split(' ')).lower().replace('.','')
        print(form.instance.slug)
        # return f"<h1> {form.instance.slug} </h1>"
        
        return super().form_valid(form)

@receiver(post_save, sender=Article)
def updateImage(sender, instance, created, **kwargs):
    if created:
        try:
            img = Image.open(instance.image.path)
        except:
            return
        else:
            if img.height > 500 or img.width > 500:
                    max_size=(300,300)                                                                                                                                                                                                                             
                    img.thumbnail(max_size)                                                                                                                                                                                                                        
                    img.save(instance.image.path)
                    instance.save()
# @receiver(post_save, sender=Article)
# def saveImage(sender, instance, created, **kwargs):


    # def get_initial(self):
    #     initial = super().get_initial()
    #     initial['title'] = 'Hello World'
    #     return initial

class AllPosts(ListView):
    template_name = 'blog/all_articles.html'
    models = Article
    context_object_name = 'article_list'
    queryset = Article.objects.all()
    paginate_by = 2

class DeleteArticle(LoginRequiredMixin, DeleteView):
    success_url = '/blog/'
    model = Article
    template_name = 'blog/delete_article.html'

class ArticleView(LoginRequiredMixin, DetailView):
    model = Article
    template_name = 'blog/articles.html'


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # for x in self.kwargs:
        #     print(x, '--', self.kwargs[x])
        pk = self.kwargs['pk']
        slug = self.kwargs['slug']

        post = get_object_or_404(Article, pk=pk, slug=slug)

        context['article'] = post

        return context

def post_comment(request, article_id):

    if request.method == 'POST':
        article = Article.objects.get(pk=article_id)
        reply = Reply(article=article, content=request.POST.get('make_post'), madeby=request.user.username)
        reply.save()

    return HttpResponseRedirect(reverse('blog:article', args=(article.id, article.slug)))

def test(request):

    return render(request, 'blog/flex.html')




