from django.db import models
import random
import string
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime

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