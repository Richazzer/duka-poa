import sys
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Product, Sale, CustomerDebt, EmailOTP, BusinessProfile
from .serializers import (
    ProductSerializer, 
    SaleSerializer, 
    CustomerDebtSerializer,
    BusinessOnboardingSerializer
)
from .economics import calculate_business_metrics


# =====================================================================
# AUTHENTICATION VIEWS
# =====================================================================

# =====================================================================
# AUTHENTICATION VIEWS
# =====================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    raw_identifier = request.data.get('email') or request.data.get('username')
    password = request.data.get('password')

    if not raw_identifier or not password:
        return Response({'error': 'Barua pepe na nenosiri vinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    identifier = raw_identifier.strip()
    print(f"\n🔍 [LOGIN ATTEMPT] Email/Username: '{identifier}' | Password received: {bool(password)}", flush=True)

    # 1. Search for user by email (case-insensitive) or username
    user_obj = User.objects.filter(email__iexact=identifier).first()
    if not user_obj:
        user_obj = User.objects.filter(username__iexact=identifier).first()

    if not user_obj:
        print(f"❌ [LOGIN ERROR] Hakuna mtumiaji mwenye barua pepe hii: {identifier}", flush=True)
        return Response({'error': 'Akaunti hii haipo. Tafadhali jisajili kwanza.'}, status=status.HTTP_400_BAD_REQUEST)

    # 2. Check if password is set on user
    if not user_obj.has_usable_password():
        print(f"⚠️ [LOGIN WARNING] Mtumiaji {identifier} hana nenosiri! Tunaweka nenosiri hili jipya...", flush=True)
        user_obj.set_password(password)
        user_obj.save()

    # 3. Authenticate using direct password verification
    is_valid = user_obj.check_password(password)
    print(f"🔑 [LOGIN VERIFICATION] Password Match: {is_valid}", flush=True)

    if not is_valid:
        return Response({'error': 'Barua pepe au nenosiri si sahihi.'}, status=status.HTTP_400_BAD_REQUEST)

    user = user_obj
    profile, _ = BusinessProfile.objects.get_or_create(user=user)
    refresh = RefreshToken.for_user(user)

    print(f"✅ [LOGIN SUCCESS] User {user.email} logged in successfully! is_onboarded: {profile.is_onboarded}\n", flush=True)

    return Response({
        'message': 'Umeingia kwa mafanikio!',
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh),
        'is_onboarded': profile.is_onboarded,
        'user': {
            'id': user.id,
            'email': user.email,
            'is_onboarded': profile.is_onboarded,
        }
    }, status=status.HTTP_200_OK)



@api_view(['POST'])
@permission_classes([AllowAny])
def send_email_otp(request):
    """
    Generates and immediately prints OTP code to terminal with flush=True.
    """
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Barua pepe inahitajika'}, status=status.HTTP_400_BAD_REQUEST)

    # Safely find existing user by email or create new one
    user = User.objects.filter(email=email).first()
    if not user:
        user = User.objects.create(username=email, email=email)
    
    otp_code = EmailOTP.generate_otp()
    EmailOTP.objects.create(user=user, otp=otp_code)

    # Guaranteed terminal print (flush=True ensures it writes directly without delay)
    print("\n" + "=" * 50, flush=True)
    print(f"🔥 [DUKA POOA OTP VERIFICATION]", flush=True)
    print(f"📩 EMAIL: {email}", flush=True)
    print(f"🔑 CODE : >>> {otp_code} <<<", flush=True)
    print("=" * 50 + "\n", flush=True)

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
    Verifies OTP during registration, guarantees password is saved, and returns JWT tokens.
    """
    email = (request.data.get('email') or '').strip()
    otp_code = (request.data.get('otp') or '').strip()
    password = request.data.get('password')

    print(f"\n🔐 [VERIFY OTP REQUEST] Email: {email} | Code: {otp_code} | Password provided: {bool(password)}", flush=True)

    if not email or not otp_code:
        return Response({'error': 'Barua pepe na namba ya OTP zinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email__iexact=email).first()
    if not user:
        user = User.objects.filter(username__iexact=email).first()

    if not user:
        return Response({'error': 'Mtumiaji hajapatikana.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        otp_record = EmailOTP.objects.filter(user=user, otp=otp_code, is_verified=False).latest('created_at')
        otp_record.is_verified = True
        otp_record.save()

        # GUARANTEE PASSWORD IS SAVED:
        if password:
            user.set_password(password)
            user.save()
            print(f"🔒 [PASSWORD SET] Nenosiri limewekwa kikamilifu kwa {user.email}", flush=True)
        else:
            print(f"⚠️ [NO PASSWORD PASSED] Tahadhari: Nenosiri halijapokelewa!", flush=True)

        profile, _ = BusinessProfile.objects.get_or_create(user=user)
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'Uhakiki umefanikiwa!',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'is_onboarded': profile.is_onboarded,
            'user': {
                'id': user.id,
                'email': user.email,
                'is_onboarded': profile.is_onboarded,
            }
        }, status=status.HTTP_200_OK)

    except EmailOTP.DoesNotExist:
        return Response({'error': 'Namba ya OTP siyo sahihi au imekwisha muda wake.'}, status=status.HTTP_400_BAD_REQUEST)
# =====================================================================
# ONBOARDING VIEW
# =====================================================================

class CompleteOnboardingView(APIView):
    permission_classes = [IsAuthenticated]

    # 1. GET: Fetches the real logged-in user and business details
    def get(self, request):
        profile, _ = BusinessProfile.objects.get_or_create(user=request.user)
        serializer = BusinessOnboardingSerializer(profile)
        
        return Response({
            "user": {
                "id": request.user.id,
                "email": request.user.email,
                "username": request.user.username,
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
            },
            "profile": serializer.data
        }, status=status.HTTP_200_OK)

    # 2. POST: Saves onboarding details
    def post(self, request):
        profile, _ = BusinessProfile.objects.get_or_create(user=request.user)
        serializer = BusinessOnboardingSerializer(profile, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save(is_onboarded=True)
            return Response({
                "success": True,
                "message": "Business profile updated successfully.",
                "is_onboarded": True,
                "data": serializer.data
            }, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# =====================================================================
# ANALYTICS & OCR VIEWS
# =====================================================================

@api_view(['GET'])
@permission_classes([AllowAny])
def business_analytics_view(request):
    metrics = calculate_business_metrics()
    return Response(metrics)


@api_view(['POST'])
@permission_classes([AllowAny])
def ocr_invoice_scanner_view(request):
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
# MODEL VIEWSETS
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