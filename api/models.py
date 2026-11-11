from django.db import models
import random
import string
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime
from django.db.models.signals import post_save
from django.dispatch import receiver

from django.conf import settings



class Product(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='products', null=True, blank=True)
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100, default='Duka')
    price = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    stock = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

class Sale(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sales', null=True, blank=True)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    payment_method = models.CharField(max_length=50, default='Cash')
    customer_name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class CustomerDebt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='debts', null=True, blank=True)
    customer_name = models.CharField(max_length=255)
    amount_owed = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    phone = models.CharField(max_length=20, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    
class EmailOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    @staticmethod
    def generate_otp():
        return str(random.randint(100000, 999999))

    def __str__(self):
        return f"{self.user.email} - {self.otp}"
    
class BusinessProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='business_profile')
    business_name = models.CharField(max_length=255, blank=True, null=True)
    business_type = models.CharField(max_length=100, blank=True, null=True)
    goals = models.TextField(blank=True, null=True)
    is_onboarded = models.BooleanField(default=False)  # <--- MUST BE False! # Tracks if they finished the splash setup

    def __str__(self):
        return f"{self.business_name or 'Pending Business'} ({self.user.username})"

# Automatically create a blank profile when a new user registers via email/OTP
@receiver(post_save, sender=User)
def create_business_profile(sender, instance, created, **kwargs):
    if created:
        BusinessProfile.objects.create(user=instance)
