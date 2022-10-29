from audioop import reverse
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.contrib.auth.models import User
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django.forms import ModelForm
from polls.models import Profile, Image





class UserSignUp(UserCreationForm):
    email = forms.EmailField(error_messages={'required':'Invalid Email Please re-enter',}, help_text="Please enter adwedd email.")
    extra = forms.CharField(empty_value="Hello World", error_messages={'required':'Please enter some shit'})
    

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-exampleForm'
        self.helper.form_class = 'blueForms'
        self.helper.form_method = 'post'
        self.helper.form_action = 'polls/test'
        self.helper.add_input(Submit('submit', 'Submit'))
        
    
    class Meta:
        model = User
        fields = ['username','email','password1','password2']




class AdditionInfo(ModelForm):
    # location = forms.CharField()
    # birthdate = forms.DateField(error_messages={'invalid':'Please input date in YYYY-MM-DD format.'} ,input_formats=['%Y-%m-%d'], widget=forms.DateInput(attrs={'placeholder': 'YYYY-MM-DD', 'class': 'date',}))
    # bio = forms.CharField(widget=forms.Textarea(attrs={'rows': 10,'cols':50}))
    # picture = forms.ImageField(allow_empty_file=True)
    class Meta:
        model = Profile
        fields = ['location', 'birthdate', 'bio', 'picture']

class ImageForm(ModelForm):
    

    class Meta:
        model = Image
        fields = ['name','image']
    
    
    

