from django.shortcuts import render


def home(request):
    context={}
    template = "polls/home.html"
    return render(request=request,template_name=template,context=context)