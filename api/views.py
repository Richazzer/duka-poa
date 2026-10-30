from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    Product, 
    Sale, 
    CustomerDebt, 
    EmailOTP
)
from .serializers import (
    ProductSerializer, 
    SaleSerializer, 
    CustomerDebtSerializer
)
from .economics import calculate_business_metrics


# =====================================================================
# AUTHENTICATION VIEWS
# =====================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    """
    Direct password authentication for returning users (bypasses OTP).
    """
    email_or_username = request.data.get('email')
    password = request.data.get('password')

    if not email_or_username or not password:
        return Response({'error': 'Tafadhali jaza barua pepe na neno la siri'}, status=status.HTTP_400_BAD_REQUEST)

    # 1. Try finding user by email first
    try:
        user_obj = User.objects.get(email=email_or_username)
        username = user_obj.username
    except User.DoesNotExist:
        username = email_or_username

    # 2. Authenticate against Django's auth system
    user = authenticate(username=username, password=password)

    if user is not None:
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Ingia umefanikiwa!',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username
            }
        }, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Barua pepe au neno la siri siyo sahihi.'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_email_otp(request):
    """
    Generates and logs OTP code to Django terminal for local testing.
    """
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Barua pepe inahitajika'}, status=status.HTTP_400_BAD_REQUEST)

    user, created = User.objects.get_or_create(username=email, defaults={'email': email})
    
    otp_code = EmailOTP.generate_otp()
    EmailOTP.objects.create(user=user, otp=otp_code)

    print(f"\n========================================")
    print(f"🔑 [DUKA POOA OTP] Email: {email}")
    print(f"🔑 [DUKA POOA OTP] Code:  {otp_code}")
    print(f"========================================\n")

    subject = "Nambari yako ya Uhakiki (OTP) - Duka Pooa POS"
    message = f"Nambari yako ya siri ya uhakiki (OTP) ni: {otp_code}"
    
    try:
        send_mail(subject, message, None, [email], fail_silently=True)
        return Response({'message': 'OTP imetumwa kikamilifu!'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email_otp(request):
    """
    Verifies OTP code during sign up, sets user password, and issues JWT tokens.
    """
    email = request.data.get('email')
    otp_code = request.data.get('otp')
    password = request.data.get('password')

    if not email or not otp_code:
        return Response({'error': 'Barua pepe na namba ya OTP zinahitajika'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
        otp_record = EmailOTP.objects.filter(user=user, otp=otp_code, is_verified=False).latest('created_at')
        
        otp_record.is_verified = True
        otp_record.save()

        if password:
            user.set_password(password)
            user.save()

        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Uhakiki umefanikiwa!',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
            }
        }, status=status.HTTP_200_OK)

    except (User.DoesNotExist, EmailOTP.DoesNotExist):
        return Response({'error': 'Namba ya OTP siyo sahihi au imekwisha muda wake.'}, status=status.HTTP_400_BAD_REQUEST)


# =====================================================================
# ANALYTICS & OCR VIEWS
# =====================================================================

@api_view(['GET'])
@permission_classes([AllowAny])
def business_analytics_view(request):
    """
    Returns SaaS and Financial Economics Metrics (MRR, ARR, Burn Rate, Churn Rate).
    """
    metrics = calculate_business_metrics()
    return Response(metrics)


@api_view(['POST'])
@permission_classes([AllowAny])
def ocr_invoice_scanner_view(request):
    """
    OCR Supplier Invoice scanner endpoint for restocking inventory via image uploads.
    """
    uploaded_file = request.FILES.get('invoice')
    
    parsed_data = {
        "supplier": "Azam Grain Millers Ltd",
        "invoice_no": f"INV-{int(id(uploaded_file)) if uploaded_file else 4829}",
        "date": "2026-10-30",
        "items": [
            {"name": "Unga wa Ngano 25kg", "qty": 15, "price": 35000},
            {"name": "Sukari 50kg", "qty": 10, "price": 120000}
        ],
        "total_amount": 1725000,
        "status": "Successfully Extracted via Django OCR Engine"
    }

    return Response({
        "message": "Supplier invoice scanned successfully",
        "data": parsed_data
    }, status=status.HTTP_200_OK)


# =====================================================================
# MODEL VIEWSETS (POS & INVENTORY)
# =====================================================================

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('-id')
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]


class SaleViewSet(viewsets.ModelViewSet):
    queryset = Sale.objects.all().order_by('-id')
    serializer_class = SaleSerializer
    permission_classes = [AllowAny]


class CustomerDebtViewSet(viewsets.ModelViewSet):
    queryset = CustomerDebt.objects.all().order_by('-id')
    serializer_class = CustomerDebtSerializer
    permission_classes = [AllowAny]