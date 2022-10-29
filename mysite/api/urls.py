from django.urls import path
from .views import article_list, article_detail
from rest_framework.urlpatterns import format_suffix_patterns

app_name = 'api'

urlpatterns = [
    path('articlelist/', view=article_list, name='article_list'),
    path('articlelist/<int:id>/', view=article_detail, name='article_detail')
]

urlpatterns = format_suffix_patterns(urlpatterns)