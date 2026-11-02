from django.db import models
import random
import string
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime
from django.db.models.signals import post_save
from django.dispatch import receiver

class Product(models.Model):
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=12, decimal_places=2)
    stock = models.IntegerField(default=0)
    image = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} (TZS {self.price})"

class Sale(models.Model):
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    payment_method = models.CharField(max_length=50, default='Cash') # Cash, Card, Mobile Money
    customer_name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Sale #{self.id} - TZS {self.total_amount}"

class CustomerDebt(models.Model):
    customer_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20, blank=True, null=True)
    amount_owed = models.DecimalField(max_digits=12, decimal_places=2)
    status = models.CharField(max_length=50, default='Pending') # Pending, Paid
    due_date = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.customer_name} owes TZS {self.amount_owed}"
    
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