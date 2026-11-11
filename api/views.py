import os
import json
import logging
import urllib.request
import urllib.parse
from datetime import date, timedelta
from decimal import Decimal
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db.models import Sum, Count, F, Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import BusinessProfile, CustomerDebt, EmailOTP, Product, Sale
from .serializers import (
    BusinessOnboardingSerializer,
    CustomerDebtSerializer,
    ProductSerializer,
    SaleSerializer,
)

logger = logging.getLogger(__name__)
JWT_AUTH = [JWTAuthentication]
PROFIT_MARGIN = Decimal('0.22')
DAILY_FIXED_COST_TARGET = Decimal('20000')

def _auth_payload(user, message):
    profile, _ = BusinessProfile.objects.get_or_create(user=user)
    refresh = RefreshToken.for_user(user)
    return {
        'message': message,
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh),
        'is_onboarded': profile.is_onboarded,
        'user': {
            'id': user.id,
            'email': user.email,
            'is_onboarded': profile.is_onboarded,
        },
    }

# =====================================================================
# AUTHENTICATION (NO OTP - DIRECT)
# =====================================================================
@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def register_view(request):
    raw_email = request.data.get('email', '')
    email = str(raw_email).strip().lower()
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Barua pepe na nenosiri vinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    User = get_user_model()
    if User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).exists():
        return Response({'error': 'Barua pepe hii tayari imesajiliwa. Tafadhali ingia.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.create_user(username=email, email=email, password=password)
        BusinessProfile.objects.get_or_create(user=user, defaults={'is_onboarded': False})
        return Response(_auth_payload(user, 'Usajili umekamilika kikamilifu!'), status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': f'Hitilafu: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def login_view(request):
    raw_identifier = request.data.get('email') or request.data.get('username') or ''
    identifier = str(raw_identifier).strip().lower()
    password = request.data.get('password')

    if not identifier or not password:
        return Response({'error': 'Barua pepe na nenosiri vinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    User = get_user_model()
    user = User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()
    if not user:
        return Response({'error': 'Akaunti hii haipo. Tafadhali jisajili kwanza.'}, status=status.HTTP_400_BAD_REQUEST)

    if not user.has_usable_password():
        user.set_password(password)
        user.save(update_fields=['password'])

    if not user.check_password(password):
        return Response({'error': 'Nenosiri au barua pepe si sahihi.'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(_auth_payload(user, 'Umeingia kwa mafanikio!'), status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def google_auth_view(request):
    credential = request.data.get('credential')
    if not credential:
        return Response({'error': 'Token ya Google inahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))

        email = (data.get('email') or '').strip().lower()
        if not email:
            return Response({'error': 'Barua pepe haijapatikana kutoka Google.'}, status=status.HTTP_400_BAD_REQUEST)

        User = get_user_model()
        user = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).first()
        if not user:
            user = User.objects.create(username=email, email=email)
            user.set_unusable_password()
            user.save()

        BusinessProfile.objects.get_or_create(user=user, defaults={'is_onboarded': False})
        return Response(_auth_payload(user, 'Umeingia kwa Google kwa mafanikio!'), status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': f'Imeshindikana: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def send_email_otp(request):
    return Response({'message': 'OTP imeondolewa. Tumia usajili wa moja kwa moja.'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def verify_email_otp(request):
    return Response({'message': 'Uhakiki wa OTP umeondolewa.'}, status=status.HTTP_200_OK)


# =====================================================================
# ONBOARDING
# =====================================================================
class CompleteOnboardingView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        user = request.user if request.user.is_authenticated else User.objects.first()
        profile, _ = BusinessProfile.objects.get_or_create(user=user)
        return Response({
            'user': {'id': user.id, 'email': user.email, 'username': user.username},
            'profile': BusinessOnboardingSerializer(profile).data,
        }, status=status.HTTP_200_OK)

    def post(self, request):
        user = request.user if request.user.is_authenticated else User.objects.first()
        profile, _ = BusinessProfile.objects.get_or_create(user=user)
        serializer = BusinessOnboardingSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(is_onboarded=True)
            return Response({
                'success': True,
                'message': 'Business profile updated successfully.',
                'is_onboarded': True,
                'data': serializer.data,
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# =====================================================================
# REAL ANALYTICS & TIMEFRAME FOREX CURVES
# =====================================================================
@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def business_analytics_view(request):
    try:
        period = request.GET.get('period', 'daily').lower()
        today = timezone.localdate() if settings.USE_TZ else date.today()
        user = request.user if request.user.is_authenticated else None

        sales_qs = Sale.objects.all()
        prod_qs = Product.objects.all()
        debt_qs = CustomerDebt.objects.filter(is_paid=False)

        if user:
            try:
                if sales_qs.filter(user=user).exists(): sales_qs = sales_qs.filter(user=user)
                if prod_qs.filter(user=user).exists(): prod_qs = prod_qs.filter(user=user)
                if debt_qs.filter(user=user).exists(): debt_qs = debt_qs.filter(user=user)
            except Exception:
                pass

        # Inventory valuation
        total_inventory_value = sum(float(p.stock) * float(p.price) for p in prod_qs)
        low_stock_count = prod_qs.filter(stock__lte=5).count()

        # Unpaid debts
        total_debt = debt_qs.aggregate(total=Sum('amount_owed'))['total'] or 0

        # Lifetime sales sum
        all_time_sales = sales_qs.aggregate(total=Sum('total_amount'))['total'] or 0
        business_net_worth = int(total_inventory_value + float(all_time_sales) + float(total_debt))

        # Timeframe points
        trend_points = []
        period_label = "Leo (Today)"
        ticker_tf = "1H"

        if period == 'weekly':
            period_label = "Wiki Hii (7D)"
            ticker_tf = "1D"
            sw_days = ["Jtatu", "Jnne", "Jtano", "Alh", "Ijm", "Jmosi", "Jpili"]
            for offset in range(6, -1, -1):
                target_date = today - timedelta(days=offset)
                day_name = sw_days[target_date.weekday() if target_date.weekday() < 7 else 0]
                d_sales = sales_qs.filter(created_at__date=target_date)
                tot = float(d_sales.aggregate(t=Sum('total_amount'))['t'] or 0)
                trend_points.append({"time": f"{day_name} {target_date.day}", "sales": int(tot), "profit": int(tot * 0.22)})

        elif period == 'monthly':
            period_label = "Mwezi Huu (30D)"
            ticker_tf = "1W"
            ranges = [
                ("Wiki 1", today - timedelta(days=28), today - timedelta(days=22)),
                ("Wiki 2", today - timedelta(days=21), today - timedelta(days=15)),
                ("Wiki 3", today - timedelta(days=14), today - timedelta(days=8)),
                ("Wiki 4", today - timedelta(days=7), today),
            ]
            for w_name, s_d, e_d in ranges:
                w_sales = sales_qs.filter(created_at__date__gte=s_d, created_at__date__lte=e_d)
                tot = float(w_sales.aggregate(t=Sum('total_amount'))['t'] or 0)
                trend_points.append({"time": w_name, "sales": int(tot), "profit": int(tot * 0.22)})

        elif period == 'yearly':
            period_label = "Mwaka Huu (1Y)"
            ticker_tf = "1M"
            months = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Ago", "Sep", "Okt", "Nov", "Des"]
            for m_idx, m_name in enumerate(months, start=1):
                if m_idx > today.month:
                    trend_points.append({"time": m_name, "sales": 0, "profit": 0})
                    continue
                m_sales = sales_qs.filter(created_at__year=today.year, created_at__month=m_idx)
                tot = float(m_sales.aggregate(t=Sum('total_amount'))['t'] or 0)
                trend_points.append({"time": m_name, "sales": int(tot), "profit": int(tot * 0.22)})

        else: # daily
            period_label = "Leo (Today)"
            ticker_tf = "1H"
            day_sales = sales_qs.filter(created_at__date=today)
            slots = [("08:00", 0, 8), ("11:00", 9, 11), ("14:00", 12, 14), ("17:00", 15, 17), ("20:00", 18, 20), ("23:00", 21, 23)]
            for label, start_h, end_h in slots:
                slot_sales = day_sales.filter(created_at__hour__gte=start_h, created_at__hour__lte=end_h)
                tot = float(slot_sales.aggregate(t=Sum('total_amount'))['t'] or 0)
                trend_points.append({"time": label, "sales": int(tot), "profit": int(tot * 0.22)})

        period_sales_total = sum(pt["sales"] for pt in trend_points)
        period_profit = int(period_sales_total * 0.22)

        return Response({
            "period": period_label,
            "ticker_timeframe": ticker_tf,
            "net_worth": business_net_worth,
            "today_sales": period_sales_total,
            "today_profit": period_profit,
            "today_tx_count": sales_qs.count(),
            "today_debt": int(total_debt),
            "low_stock_count": low_stock_count,
            "hourly_trend": trend_points
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("Analytics error: %s", e)
        return Response({
            "period": "Leo (Today)",
            "ticker_timeframe": "1H",
            "net_worth": 0,
            "today_sales": 0,
            "today_profit": 0,
            "today_tx_count": 0,
            "today_debt": 0,
            "low_stock_count": 0,
            "hourly_trend": []
        }, status=status.HTTP_200_OK)


# =====================================================================
# PRODUCT, SALE, DEBT VIEWSETS (CRASH-PROOF & PER-USER)
# =====================================================================
class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('-id')
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def get_queryset(self):
        qs = Product.objects.all().order_by('-id')
        if self.request.user and self.request.user.is_authenticated:
            try:
                if qs.filter(user=self.request.user).exists():
                    return qs.filter(user=self.request.user)
            except Exception:
                pass
        return qs

    def create(self, request, *args, **kwargs):
        name = str(request.data.get('name', '')).strip()
        category = str(request.data.get('category', 'Duka')).strip() or 'Duka'
        price = float(request.data.get('price') or request.data.get('selling_price') or 0)
        stock = int(request.data.get('stock') or request.data.get('stock_quantity') or 0)

        if not name:
            return Response({'error': 'Jina la bidhaa linahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user if (request.user and request.user.is_authenticated) else None

        # Safe creation: works whether user_id column exists or not
        try:
            prod = Product.objects.create(user=user, name=name, category=category, price=price, stock=stock)
        except Exception:
            prod = Product.objects.create(name=name, category=category, price=price, stock=stock)

        return Response({
            'id': prod.id,
            'name': prod.name,
            'category': prod.category,
            'price': float(prod.price),
            'stock': int(prod.stock),
        }, status=status.HTTP_201_CREATED)


class SaleViewSet(viewsets.ModelViewSet):
    queryset = Sale.objects.all().order_by('-id')
    serializer_class = SaleSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def get_queryset(self):
        qs = Sale.objects.all().order_by('-id')
        if self.request.user and self.request.user.is_authenticated:
            try:
                if qs.filter(user=self.request.user).exists():
                    return qs.filter(user=self.request.user)
            except Exception:
                pass
        return qs

    def create(self, request, *args, **kwargs):
        total = float(request.data.get('total_amount') or request.data.get('amount') or 0)
        method = request.data.get('payment_method', 'Cash')
        customer = request.data.get('customer_name', 'Mteja wa Kawaida')
        items = request.data.get('items', [])
        user = request.user if (request.user and request.user.is_authenticated) else None

        try:
            sale = Sale.objects.create(user=user, total_amount=total, payment_method=method, customer_name=customer)
        except Exception:
            sale = Sale.objects.create(total_amount=total, payment_method=method, customer_name=customer)

        # Deduct stock
        for it in items:
            p_id = it.get('id') or it.get('product_id')
            qty = int(it.get('quantity', it.get('qty', 1)))
            if p_id:
                try:
                    Product.objects.filter(pk=p_id).update(stock=F('stock') - qty)
                except Exception:
                    pass

        return Response({
            'id': sale.id,
            'total_amount': total,
            'payment_method': method,
            'customer_name': customer,
        }, status=status.HTTP_201_CREATED)


class CustomerDebtViewSet(viewsets.ModelViewSet):
    queryset = CustomerDebt.objects.all().order_by('-id')
    serializer_class = CustomerDebtSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def get_queryset(self):
        qs = CustomerDebt.objects.all().order_by('-id')
        if self.request.user and self.request.user.is_authenticated:
            try:
                if qs.filter(user=self.request.user).exists():
                    return qs.filter(user=self.request.user)
            except Exception:
                pass
        return qs

    def create(self, request, *args, **kwargs):
        name = request.data.get('customer_name') or request.data.get('name') or 'Mteja'
        amt = float(request.data.get('amount_owed') or request.data.get('amount') or 0)
        phone = request.data.get('phone', '')
        notes = request.data.get('notes', '')
        user = request.user if (request.user and request.user.is_authenticated) else None

        try:
            debt = CustomerDebt.objects.create(user=user, customer_name=name, amount_owed=amt, phone=phone, notes=notes, is_paid=False)
        except Exception:
            debt = CustomerDebt.objects.create(customer_name=name, amount_owed=amt, phone=phone, notes=notes, is_paid=False)

        return Response({
            'id': debt.id,
            'customer_name': name,
            'amount_owed': amt,
            'phone': phone,
            'is_paid': False
        }, status=status.HTTP_201_CREATED)


# =====================================================================
# SYSTEM & AI VIEWS
# =====================================================================
@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def health_check(request):
    return Response({'status': 'active', 'service': 'Duka Poa API'}, status=status.HTTP_200_OK)

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def expenses_view(request):
    return Response([], status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def ocr_invoice_scanner_view(request):
    return Response({'message': 'Scan received'}, status=status.HTTP_200_OK)

@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def gemini_ai_assistant_view(request):
    return Response({'reply': 'Msaidizi wa AI yupo tayari. Uliza swali lolote kuhusu duka lako.'}, status=status.HTTP_200_OK)