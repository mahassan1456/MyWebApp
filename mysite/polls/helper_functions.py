from polls.models_profile import Comments
from django.utils import timezone

def check_flag_n_comment(request,user,comm = False):
    if comm:
        comment = Comments(user_c=user, comment=request.POST.get('comment'), posted_by=request.user.username)
        comment.save()
    try:
        last_post_time = user.comments_set.last().post_date 
        last_checked_time = user.notification.comments_last_time
    except AttributeError as E:
        print(E)
        return False
    else:
        if request.user != user:
            if last_post_time > last_checked_time:
                user.notification.comment_flag = True
                user.notification.save()
        elif request.user == user:
            request.user.notification.comment_flag = False
            request.user.notification.comments_last_time = timezone.now()
            request.user.notification.save()
        return user.notification.comment_flag

def key(id,id1):
    query = str(id) + '-' + str(id1) if id < id1 else str(id1) + '-' + str(id)
    return query