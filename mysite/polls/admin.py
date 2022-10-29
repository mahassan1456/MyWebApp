from django.contrib import admin



from polls.models import Question, Choice, Comments, Circle, DM

# Register your models here.

class ChoiceInline(admin.TabularInline):
    model= Choice
    extra = 3

class QuestionAdmin(admin.ModelAdmin):

    fieldsets = [
        ('Question', {'fields': ['question_text']}),
        ('Date Information', {'fields': ['pub_date']})
    ]
    inlines = [ChoiceInline]
    list_display = ('question_text', 'pub_date','was_published_recently')

admin.site.register(Question, QuestionAdmin)

admin.site.register(Comments)

admin.site.register(Choice)

admin.site.register(DM)

admin.site.register(Circle)





