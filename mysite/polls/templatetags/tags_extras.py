from django import template


register = template.Library()

@register.filter
def indexed(index, list):
    return index[list]