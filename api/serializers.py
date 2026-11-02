from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from .models import Product, Sale, CustomerDebt
from .models import BusinessProfile

User = get_user_model()

# 1. Model Serializers used by your ViewSets
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

# 2. Custom JWT Serializer for Email Authentication
class EmailTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if not email or not password:
            raise serializers.ValidationError("Must include 'email' and 'password'.")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("No active account found with the given credentials.")

        if not user.check_password(password):
            raise serializers.ValidationError("No active account found with the given credentials.")

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")

        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        
class BusinessOnboardingSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessProfile
        fields = ['business_name', 'business_type', 'goals', 'is_onboarded']
        read_only_fields = ['is_onboarded']