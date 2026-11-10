from rest_framework import serializers
from .models import Product, Sale, CustomerDebt, BusinessProfile

class ProductSerializer(serializers.ModelSerializer):
    # Aliases: accepts both frontend and database naming conventions
    selling_price = serializers.DecimalField(source='price', max_digits=12, decimal_places=2, required=False)
    stock_quantity = serializers.IntegerField(source='stock', required=False)

    class Meta:
        model = Product
        fields = '__all__'


class SaleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sale
        fields = '__all__'


class CustomerDebtSerializer(serializers.ModelSerializer):
    # Alias: accepts both 'amount' and 'amount_owed'
    amount = serializers.DecimalField(source='amount_owed', max_digits=12, decimal_places=2, required=False)

    class Meta:
        model = CustomerDebt
        fields = '__all__'


class BusinessOnboardingSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessProfile
        fields = '__all__'
