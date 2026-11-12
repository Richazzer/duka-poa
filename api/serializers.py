
from rest_framework import serializers
from .models import Product, Sale, CustomerDebt, BusinessProfile

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'
        read_only_fields = ('user',)


class SaleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sale
        fields = '__all__'
        read_only_fields = ('user',)


class CustomerDebtSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerDebt
        fields = '__all__'
        read_only_fields = ('user',)


class BusinessOnboardingSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessProfile
        fields = '__all__'
        read_only_fields = ('user',)
