from rest_framework import serializers
from .models import Product, Sale, CustomerDebt

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'

class SaleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sale
        fields = '__all__'

class CustomerDebtSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerDebt
        fields = '__all__'