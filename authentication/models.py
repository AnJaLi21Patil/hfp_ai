
# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_email_verified = models.BooleanField(default=False)  # 🔹 Add this field

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
