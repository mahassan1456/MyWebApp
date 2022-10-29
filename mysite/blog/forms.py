from django.forms import ModelForm
from .models import Article, Reply
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit


class ArticleForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-exampleForm'
        self.helper.form_class = 'container'
        self.helper.form_method = 'post'
        self.helper.form_action = ""
        self.helper.add_input(Submit('submit', 'Submit'))
    class Meta:
        model= Article
        fields = ['title','image', 'content']

class ReplyForm(ModelForm):

    class Meta:
        model = Reply
        fields = ['content']