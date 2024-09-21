from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.core.mail import send_mail
from django.db.models.signals import post_save
from django.dispatch import receiver
import logging


class Role(models.Model):
    class Roles(models.TextChoices):
        ADMIN = "admin", "Admin"
        EMPLOYEE = "employee", "Employee"


class User(AbstractUser):

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=120)
    username = models.CharField(max_length=120, unique=True)
    last_login = models.DateTimeField(auto_now=True)
    role = models.CharField(choices=Role.Roles.choices, max_length=20)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "username"]

    def __str__(self):
        return self.name


logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def send_welcome_email(sender, instance, created, **kwargs):
    if created:
        subject = "Welcome to Our Service"
        message = f"Hi {instance.username}, welcome to our service!"
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [instance.email]
        try:
            send_mail(
                subject,
                message,
                from_email,
                recipient_list,
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Error sending email: {e}")
