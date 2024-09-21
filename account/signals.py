# from django.conf import settings
# from django.core.mail import send_mail
# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from .models import User
# import logging
#
#
# logger = logging.getLogger(__name__)
#
# @receiver(post_save, sender=User)
# def send_welcome_email(sender, instance, created, **kwargs):
#     if created:
#         subject = 'Welcome to Our Service'
#         message = f'Hi {instance.username}, welcome to our service!'
#         from_email = settings.EMAIL_HOST_USER
#         recipient_list = [instance.email]
#         try:
#             send_mail(
#                 subject,
#                 message,
#                 from_email,
#                 recipient_list,
#                 fail_silently=False,
#             )
#         except Exception as e:
#             logger.error(f"Error sending email: {e}")
#
#
#
