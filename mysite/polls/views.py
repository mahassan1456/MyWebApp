from calendar import c
from tempfile import template
from django.http import HttpResponse, Http404, HttpResponseRedirect, JsonResponse
from .models import Question, Choice, Profile, Circle, Comments, DM, DmThrough, Notification
from django.template import loader, Context
from django.shortcuts import render, get_object_or_404
from django.urls import reverse
from django.views import generic
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import login,authenticate, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from polls.forms import UserSignUp, AdditionInfo, ImageForm
from django.contrib import messages
import datetime
from django.core.signals import request_finished
from PIL import Image
from django.db.models import Q
from blog.models import Article
from django.apps import apps
from polls.helper_functions import key, check_flag_n_comment
from django.core.mail import send_mail
import jwt
import smtplib, ssl
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.contrib.auth.hashers import make_password, check_password


############################## SEND EMAIL #######################
KEY = "This is my motherfucking secret key.43423r234r24r2wrw4r4tfrsfsdffgedg"

def test_popup(request):
    return render(request, 'polls/popup.html')
############################## RETURN USER LISTS ###############################


class UserList(generic.ListView):
    template_name = 'polls/querylist.html'
    model = User
    context_object_name = 'search_list'

    def get_queryset(self):
        option = self.request.GET.get('option')
        query = self.request.GET.get('q')
        if option == 'User':
            q_list = User.objects.filter(Q(username__icontains = query) | Q(email__icontains = query))
            
        else:
            q_list = Question.objects.filter(Q(question_text__icontains = query) | Q(question_text__icontains = query))
            
        
        return q_list

def listUser(request):

    return render(request,'polls/listuser.html')

def getUser(request):

    lis = User.objects.all()
    return JsonResponse({'users': list(lis.values())})



################## ALL THIGNS RELATING TO PROFILE MANAGEMENT ##################


@login_required
def success(request):
    if request.method == 'POST':
        # request.FILES['picture']= request.user.profile.picture if True else ''
        form = AdditionInfo(request.POST, request.FILES, instance=request.user.profile)
        if form.is_valid():
            form.save()
            # request.user.profile.rs()
            
            # instance = form.save()
            # instance.user = request.user
            # instance.save()
            # # request.user.profile.bio = form.cleaned_data.get('bio')
            # # request.user.profile.location = form.cleaned_data.get('location')
            # # request.user.profile.birthdate = form.cleaned_data.get('birthdate')
            # # if form.cleaned_data.get('picture') != request.user.profile.picture:
            # #     request.user.profile.picture = form.cleaned_data.get('picture')

            # # request.user.save()
            return HttpResponseRedirect(reverse('polls:index'))
    
    # form = AdditionInfo(initial={'bio': request.user.profile.bio, 'location':request.user.profile.location,'birthdate':request.user.profile.birthdate})
    form = AdditionInfo(instance=request.user.profile)
    
    return render(request, 'polls/success.html', {'form': form})

@login_required
def make_comment(request,user_id):
    user = User.objects.get(pk=user_id)
    # if request.user == user:
    #     request.user.notification.comments_last_time = timezone.now()
    #     request.user.save()
    #     request.user.notification.save()
    check_flag_n_comment(request,user, True)

    # comment = Comments(user_c=user, comment=request.POST.get('comment'), posted_by=request.user.username)
    # comment.save()

    return render(request, 'polls/view_profile.html', {'user': user})

@login_required
def view_profile(request, user_id):
    # try:
    #     notification = request.user.notification
    # except Notification.DoesNotExist as error:
    #     notif = Notification(user_n = request.user)
    #     notif.save()
    #     request.user.save()
    # if request.user.profile:
    #     return render(request, 'polls/view_profile.html')
    # if request.user.id != user_id:


    user = User.objects.get(pk=user_id)
    # if request.user == user:
    #     request.user.notification.comment_flag = False
    #     request.user.notification.comments_last_time = timezone.now()
    #     request.user.notification.save()
    check_flag_n_comment(request,user)
    # if user == request.user:
    #     request.user.notification.comments_last_time = timezone.now()
    #     request.user.notification.save()

    return render(request, 'polls/view_profile.html', {'user': user})

@login_required
def profile_settings(request):
    if request.method == 'POST':
        answer = request.POST.get('answer','')
        request.user.profile.canView = answer
        request.user.save()
        return HttpResponseRedirect(reverse('polls:view_profile', args=(request.user.id,)))
    return render(request,'polls/profile_settings.html')




############################## LOG IN/LOG OUT/ HOME ################################

def forgot_password(request):
    result = False
    result1 = False
    if request.method == 'POST':
        email = request.POST.get('resetemail','')
        try:
            requested_user = User.objects.get(email=email)
        except (User.DoesNotExist, KeyError) as e:
            print(e)
            result1 = True
        else:
            payload = {
                "id": requested_user.id,
                "fir": requested_user.first_name,
                "lst": requested_user.last_name
            }
            token = jwt.encode(key=KEY,payload=payload)
            link = f'127.0.0.1/polls/newpassword/?token={token}&id={requested_user.id}'
            result = True
            sender_email = 'accounts@randomthoughtz.com'
            receiver_email  = requested_user.email
            smtp_server = 'mail.privateemail.com'
            port = 465
            login = "accounts@randomthoughtz.com"
            password = "Iverson01"
            message = MIMEMultipart('alternative')
            message["Subject"] = "Reset Your Password for RandomThoughtz.Com"
            message["From"] = f"Accounts<{sender_email}>"
            message["To"] = receiver_email
            text = f"""\
                    Please copy and paste the following link in your browser \n
                    {link}
                    """
            html = """\
                    <html>
                    <head>
                    </head>
                    <body>
                        <p>Hi, {title}<br>
                        <br>
                        Please Click the Link Below to securely reset your Password
                        <a href="{link}">Reset Password</a> 
                        </p>
                    </body>
                    </html>
                    """.format(title=requested_user.first_name, link=link)
            part1 = MIMEText(text, "plain")
            part2 = MIMEText(html, "html")
            message.attach(part1)
            message.attach(part2)
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL(smtp_server,port=port, context=context) as server:
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message.as_string())

        return render(request, 'polls/forgotpassword.html', context={'result':result,'result1':result1})

    return render(request, 'polls/forgotpassword.html', context={'result':result,'result1':result1})

def newpassword(request):
    #verify if jwt is okay and also
    user = User.objects.get(id=request.GET.get('id'))
    token = request.GET.get('token','')
    result = jwt.decode(key=KEY,jwt=token,algorithms=['HS256',])
    direct = 1
    if result:
        if request.method == 'POST':
            password1 = request.POST.get('password1','')
            password2 = request.POST.get('password2','')
            if password1 == password2:
                password = make_password(password=password1)
                user.password = password
                user.save()
                messages.success("Email Successfully Sent")
                
            else:
                messages.error("Passwords Do Not Match")
            # return render(request, 'polls/newpassword.html',{'direct':direct})
        else:
            messages.info("Please enter new Password")
            direct = 2
        #     return render(request, 'polls/newpassword.html', {'direct':direct})
        # return render(request, 'polls/newpassword.html')
    else:
        messages.error("Error Processing Link")
    return render(request,'polls/newpassword.html',{'direct':direct,'result':result})

def login_user(request):
    if request.method == 'POST':
        
        username = request.POST['username'].lower()
        password = request.POST['password']
        user = authenticate(request,username=username,password=password)
        url = request.GET.get('next', '')
        if user is not None:
            login(request, user)
            try:
                notification = user.notification
            except Notification.DoesNotExist as error:
                notif = Notification(user_n = user)
                notif.save()
                request.user.save()
            return HttpResponseRedirect(url if url else reverse('polls:view_profile', args=(user.id,)))
            # # return HttpResponseRedirect(reverse('polls:success'))
            # if url:
            #     print(url)
            #     return HttpResponseRedirect(url)
            # else:
            #     print("testsuccess")
            #     print(url)
            #     return HttpResponseRedirect(reverse('polls:view_profile', args=(user.id,)))

        else:
            
            messages.success(request, "Username or Password is Incorrect")
            return HttpResponseRedirect(reverse('polls:login_user'))
    
    user = False
    return render(request, 'polls/login.html', context={"user": user})

def logout_user(request):
    logout(request)
    return HttpResponseRedirect(reverse('polls:login_user'))


def sign_up(request):
    if request.method == 'POST':
        print("t----", request.POST.get('t', "non existant"))
        first = request.POST['first']
        last = request.POST['last']
        email = request.POST['email'].lower()
        password = request.POST['password']
        password2 = request.POST['password2']
        if password == password2:
            new_user = User.objects.create_user(email=email,username=email, password=password,first_name=first, last_name=last)
            new_user.save()
            return HttpResponseRedirect(reverse('polls:login_user'))
        else:
            return render(request, 'polls/sign_up.html', context= {'error_message': "Please enter the same unique password"} )
    return render(request, 'polls/sign_up.html' )




################## FUNCTIONS RELATED TO FRIEND REQUESTS FR-7 ##################


@login_required
def cancel_request(request, user_id):
    request.user.user.unrequest(user_id)
    return render(request, 'polls/friend_request.html')

@login_required
def add_friend(request, user_id):

    # usee = User.objects.get(pk=user_id)
    # print(usee)
    # friender = User.objects.get(pk=user_id)
    # friender.user.requests.add(request.user)
    # friender.save()
    # request.user.user.sent_requests.add(friender)
    # request.user.save()

    request.user.user.send_request(user_id)
    friend = User.objects.get(pk=user_id)
    friend.notification.request_flag = True
    friend.notification.friend_last_time = timezone.now()
    friend.notification.save()
    friend.save()
    messages.success(request,f"You have sent a request to {friend.username} ")
    return HttpResponseRedirect(reverse('polls:index'))   

@login_required
def accept_request(request, user_id):
    # if len(request.user.user.requests.all()) >= 1:
    #     request.user.notification.request_flag = False
    #     request.user.notification.friend_last_time = timezone.now()
    #     request.user.notification.save()

    request.user.user.accept(user_id)
    messages.success(request, f"You are now friends with {User.objects.get(pk=user_id).username}")
    return render(request, 'polls/friend_request.html')

def remove_friend(request,user_id):
    request.user.user.remove_friend(user_id)
    messages.success(request, f"You are no longer friends with {User.objects.get(pk=user_id).username}")
    return render(request, 'polls/friend_request.html')

def view_requests(request):
    notif = []
    mutuals = request.user.user.is_mutual()
    for req in request.user.user.requests.all():
        if req.user.to_notify:
            notif.append((req,True))
            req.user.to_notify = False
            req.user.save()
        else:
            notif.append((req,False))
        req.user.save()
    return render(request, 'polls/friend_request.html', {'mutuals': mutuals, "notify": notif, "loop":range(len(notif))})




######## FUNCTIONS RELATED TO VOTING/CREATING QUESTION/ ANSWERING VT-1 ########


@login_required
def index(request):
    
    latest_question_list = Question.objects.order_by('-pub_date')
    template = loader.get_template('polls/index.html')
    context = {
        'latest_question_list': latest_question_list,
        'Users' : User.objects.all()
    }

    return HttpResponse(template.render(context, request))

def chart(request, question_id):
    labels =[]
    data = []
    qset = Choice.objects.filter(question= question_id)
    for dat in qset:
        labels.append(dat.choice_text)
        data.append(dat.votes)
    

    return render(request, 'polls/chart.html', {
    'labels': labels,
    'data': data,
    'question': Question.objects.get(pk=question_id).question_text
})

@login_required
def detail(request, question_id):
    try:
        question = Question.objects.get(pk=question_id)
    except Question.DoesNotExist:
        raise Http404("This Question Does Not Exist")
    return render(request,'polls/details.html', context={'question': question})

@login_required
def results(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    return render(request, 'polls/results.html', {'question': question})

def vote(request,question_id):
    question = get_object_or_404(Question, pk=question_id)
    if request.POST.get('edit','') == 'Edit':
        return HttpResponseRedirect(reverse('polls:edit', args=(question_id,)))
    
    elif request.POST.get('delete',''):
        print(request.POST.get('delete'))
        question.delete()
        return HttpResponseRedirect(reverse('polls:index'))
    
    try:
        choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        context = {
            'question': question,
            'error_message': 'You did not submit a vote'
        }
        return render(request, 'polls/details.html', context)
    else:
        for item in request.user.choice_set.filter(question=choice.question):
            if choice.question == item.question:
                item.votes -= 1
                item.save()
                request.user.choice_set.remove(item)
                break
            
        choice.users.add(request.user)
        choice.save()
        choice.votes += 1
        choice.save()
        
        return HttpResponseRedirect(reverse('polls:results', args=(question.id,)))

@login_required
def add_question(request):
    if request.method == 'POST':
        
        question = request.POST.get('question','')
        if question:
            request.user.question_set.create(question_text=question, pub_date=timezone.now())
            request.user.save()
            # choices = request.POST.get('choices','')
            array = []
            for x in range(1,10):
                name = "choice" + str(x)
                word = request.POST.get(name,"nada")
                if word == "nada":
                    break
                array.append(word)
            
            print(array)
            # choices_list = [x.strip() for x in choices.split('\n')]
            for x in array:
                request.user.question_set.get(question_text=question).choice_set.create(choice_text=x, votes=0)
                request.user.save()
            return HttpResponseRedirect(reverse('polls:index'))

    return render(request, 'polls/add_question.html')

@login_required
def edit(request, question_id):
    question = request.user.question_set.get(pk=question_id)
    if request.method == 'POST':
        question.deleteChoices(request.POST.get('question'), request.POST.get('choices',''))
        return HttpResponseRedirect(reverse('polls:index'))



    
    return render(request, 'polls/edit.html', {'question':question})



####################### MESSAGES AND ALL OTHER NOTIFICATIONS ####################


@login_required
def dm(request, id):
    # User first enters a private Chat
    #1) if user is making a post request then we know that the friend is the other user
    # and his notification flag should automatically be set
    friend = User.objects.get(pk=id)
    # query = str(request.user.id) + '-' + str(friend.id) if request.user.id < friend.id else str(friend.id) + '-' + str(request.user.id)
    # helper function designed to create key for parent chat conversation object.
    key1 = key(request.user.id,id)
    if request.method == 'POST':
        if friend not in request.user.user.chats.all():
            print("????")
            request.user.user.chats.add(friend)
            friend.user.chats.add(request.user)
        # Try to pull from table if conversation exists
        try:
            print("try get DmThrough")
            dmt = DmThrough.objects.get(pk=key1)
        # create new entry for conversation if key does not exist
        except (KeyError, DmThrough.DoesNotExist):
            print('error')
            dmt = DmThrough.objects.create(id = key1,new_messages=True, 
            who_last = request.user.username, who_last_u= friend)
            # dmt.create_key(request.user.id, id)
        # reset the new_messages flag after new message 
        else:
            dmt.new_messages = True
            # dmt.who_last_u == friend
        # input new message into message table and reset flag to indicate new_messages 
        # are available.
        message = request.POST.get('message')
        dm = DM(comp=dmt, mb=request.user,fw=friend, message=message, usermade=request.user.username)
        dmt.new_messages = True
        print(friend)
        friend.notification.chat_flag = True
        friend.notification.save()
    
        dmt.who_last_u = friend
        dm.save()
        dmt.save()                   

        return HttpResponseRedirect(reverse('polls:dm', args=(friend.id,)))
    # dm = DM.objects.filter(comp__iregex=f'({request.user.id}-{friend.id})|({friend.id}-{request.user.id})')
    dm = DM.objects.filter(comp=key1)
    print("test")
    # dmt = DmThrough.objects.filter(pk=key1)[0]
    # does not enter  the "if block" and comes here and if the Request is a GET
    # if the request.user is not equal to friend then we know we should do nothign and
    # 
    try:
        dmt = DmThrough.objects.filter(pk=key1)[0]
        if dmt.who_last_u == request.user:
            if len(DmThrough.objects.filter(who_last_u=request.user)) == 1:
                request.user.notification.chat_flag = False
                request.user.notification.save()
            print('yes')
            dmt.new_messages = False
            dmt.who_last_u = None
            # request.user.notification.chat_flag = False
            # request.user.notification.save()
            # dmt.who_last_u = friend
            dmt.save()
    except (KeyError, DmThrough.DoesNotExist) as e:
        print('error')
    finally:
        return render(request,'polls/dm.html', {'dm':dm, 'friend': friend, 'yes': len(dm)})

def updatechat(request, id, id2):
    #######DANGERRRRRRRR MAY REMOVE IF BUGGY ########
    query = key(id,id2)
    if request.user == User.objects.get(pk=id2):
        pass
    notifics = DmThrough.objects.filter(who_last_u = request.user)
    print(len(notifics))
    if (request.user.notification.chat_flag and len(notifics) == 1):
        notifics = notifics[0]
        notifics.who_last_u = None
        notifics.save()
        request.user.notification.chat_flag = False
        request.user.notificiation.save()
    ###################### END DANGER ########################
    print(request.user.notification,request.user)
    query = str(id) + '-' + str(id2) if id < id2 else str(id2) + '-' + str(id)
    #call key function to generate message thread ID
    query = key(id,id2)
    #fetch all messages for current thread
    chats_r = DM.objects.filter(comp=query)
    #return JsonResponse as Javascript response object
    return JsonResponse({'chats': list(chats_r.values()), 'current_u': request.user.username})

def chats(request):

    # if (len(DmThrough.objects.filter(who_last_u = request.user)) == 1 and 
    # request.user.notification.chat_flag):
    #     request.user.notification.chat_flag = False
    #     request.user.notification.save()
    
    request.user.notification.save_chat_time()
    # this is where I ws before I deleted.
    ##############
    # request.user.notification.chat_flag = False
    # request.user.notification.save() 
    ##############
    # once chats page is visited clear notifications for the notified user
    notify = []
    # for chat in DmThrough.objects.filter(who_last_u = request.user):
    #     chat.new_messages = False
    #     chat.save()
    #     spl = chat.id.split('-')[0] if chat.id.split('-')[0] != request.user.id else chat.id.split('-')[1]
    #     for thrd in request.user.user.chats.all():
    #         print(thrd.id)
    #         if thrd.id == spl:
    #             notif.append((thrd, True))
    #             spl = 'found'
    #             break
    #     if spl != 'found':
    #         notif.append((chat,False))
    spl= None
    flag = False
    x= 0
    limit = len(request.user.user.chats.all())
    # Loop Through Every chat and match them to the chats which have who_last_u set to me
    for thread_x in request.user.user.chats.all():
        spl=True
        for chat in DmThrough.objects.filter(who_last_u = request.user):
            # if not chat.new_messages:
            #     break
            spl = int(chat.id.split('-')[0] if int(chat.id.split('-')[0]) != request.user.id else chat.id.split('-')[1])
            
            if spl == thread_x.id:
                notify.append((thread_x,True))
                spl = False
                flag = True
                chat.new_messages = False
                chat.save()
                # request.user.notification.stop_script = True
                # request.user.notification.save()
                break

        if spl:
            notify.append((thread_x,False))
            x += 1
    if x >= limit:
        print(request.user, "enter in", x , "-", limit)
        request.user.notification.chat_flag = False
        request.user.notification.save() 
    print(x, "   This is a test to see if this is 1.")
    return render(request, 'polls/chats.html', {"chats": notify})

@login_required
def chat_notify(request):
    if (len(DmThrough.objects.filter(who_last_u = request.user)) == 1 and 
    request.user.notification.chat_flag):
        # request.user.notification.chat_flag = False
        # request.user.notification.save()
        pass
    test = False
    print(request.user,"XXXX",request.user.notification.chat_flag)
    if request.user.notification.chat_flag:
        test = True
        # request.user.notification.chat_flag = True
        # request.user.notification.chat_flag.save()
    # dm = DmThrough.objects.get(pk= key(request.user.id,id_friend))
    print(request.user.notification.chat_flag, request.user.username)
    query = DmThrough.objects.filter(who_last_u = request.user)
    notify = False
    # for q in query:
    #     if q.new_messages == True:
    #         notify = True
    #         break
    if len(query) >= 1:
        notify = True
        # request.user.notification.chat_flag = True
        # request.user.notification.chat_flag.save()
    return JsonResponse({"notify": notify,"test": test})
  
def fr_request_notify(request):
    if len(request.user.user.requests.all()):
        return JsonResponse({'notify': True})
        
    return JsonResponse({'notify': False})

def comment_notif(request,user_id):
    user = User.objects.get(pk=user_id)
    notify = check_flag_n_comment(request,user)
    # if request.user != user and \
    # user.comments_set.last().posted_by == request.user.username:
    #     if user.comments_set.last().post_date > user.notification.comments_last_time:
    #         user.notification.comment_flag = True
    #         user.notification.save()
    #         notify = True
    #         return JsonResponse({'notify': notify})
        
   
    # request.user.notifcation.comments_last_time = timezone.now()
    # request.user.notification.save()
    return JsonResponse({'notify': notify})

def check_profile_flag(request):
    notify = False
    if request.user.notification.comment_flag:
        notify = True
    return JsonResponse({"notify": notify})

# def set_False(request):
#     request.user.notification.stop_script = False
#     request.user.notification.save()
def clear_chat_notify(request):
    for notif_chat in DmThrough.objects.filter(who_last_u = request.user):
        notif_chat.who_last_u = None
        notif_chat.save()
    request.user.notification.chat_flag = False
    request.user.notification.save() 
    return HttpResponseRedirect(reverse('polls:chats',))
    
def clear_notifi(request, id):
    flag = False
    kkey = key(request.user.id, id)

    for chat in DmThrough.objects.filter(who_last_u = request.user):
        if chat.id == kkey:
            chat.who_last_u = None
            chat.save()
            flag = True
            break

   
    return HttpResponseRedirect(reverse('polls:chats',))

    
    


#####################################  END ##########################################################


### TEST FUNCTON ####
def test123(request):
    articles = Article.objects.all()
    return render(request,'admin/test123.html',context={'articles':articles})

# Another way of getting Models from apps and helps to avoid circular imports

# Article = apps.get_model('blog','Article')

# def finished(sender, **kwargs):
#     print("testing if request finished")
#     print(sender)

# request_finished.connect(finished)
# def image(request):
#     if request.method == 'POST':
#         print('tttt')
#         form = ImageForm(request.POST or None, request.FILES or None)
#         if form.is_valid():
#             print("valid")
#             form.save()
   
#     form = ImageForm()
#     return render(request, 'polls/images.html', {'form': form} )


# @login_required
# def other_profile(request, user_id):


# def test(request):
#     if request.method == 'POST':
#         form = UserSignUp(request.POST)
#         if form.is_valid():
#             form.save()
#             print(form.cleaned_data.get('extra',''))
#             messages.success(request, "You have successfully signed up")
#         else:
#             messages.error(request, "Username already exists")

#     else:
#         form = UserSignUp()
#     return render(request, 'polls/test.html', {'form': form })