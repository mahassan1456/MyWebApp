from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import Article, Tags, Reply

class ArticleAdmin(admin.ModelAdmin):
    list_display = ('title', 'created', 'updated')
    list_filter = ('tags', 'created', 'updated')
    search_fields = ('title',)
    prepopulated_fields = {'slug': ('title',)} # this create the slug field from the title field
    autocomplete_fields = ('tags',)

admin.site.register(Article, ArticleAdmin)

# TagAdmin must define "search_fields", because it's referenced by PostAdmin.autocomplete_fields.
class TagsAdmin(admin.ModelAdmin):
    search_fields = ('tag',)

admin.site.register(Tags, TagsAdmin)

admin.site.register(Reply)
