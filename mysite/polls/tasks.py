

# feedback/tasks.py

from time import sleep
from django.core.mail import send_mail
from celery import shared_task

@shared_task()
def send_feedback_email_task(email_address, message):
    # """Sends an email when the feedback form has been submitted."""
    # sleep(20)  # Simulate expensive operation(s) that freeze Django
    # send_mail(
    #     "Your Feedback",
    #     f"\t{message}\n\nThank you!",
    #     "specialreminder@gmail.com",
    #     [email_address],
    #     fail_silently=False,
    sleep(10)
    print(email_address, message)
    