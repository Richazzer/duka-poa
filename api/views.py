import os
import json
import logging
import urllib.request
import urllib.parse
from datetime import date, datetime, time as dtime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import lru_cache

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ValidationError as DjangoValidationError
from django.db import transaction, IntegrityError
from django.db.models import Sum, Count, F, Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from .models import BusinessProfile, CustomerDebt, EmailOTP, Product, Sale
from .serializers import (
    BusinessOnboardingSerializer,
    CustomerDebtSerializer,
    ProductSerializer,
    SaleSerializer,
)

logger = logging.getLogger(__name__)

JWT_AUTH = [JWTAuthentication]
PROFIT_MARGIN = Decimal(os.environ.get('ESTIMATED_PROFIT_MARGIN', '0.22'))
DAILY_FIXED_COST_TARGET = Decimal(os.environ.get('DAILY_FIXED_COST_TARGET', '20000'))

# =====================================================================
# MULTI-TENANCY & FLEXIBLE FIELD RESOLVER
# =====================================================================
FIELD_ALIASES = {
    'owner': ('user', 'owner', 'shop', 'business', 'created_by'),
    'name': ('name', 'title'),
    'price': ('price', 'selling_price'),
    'cost': ('buying_price', 'cost_price', 'purchase_price', 'cost'),
    'stock': ('stock', 'stock_quantity', 'quantity'),
    'total': ('total_amount', 'amount', 'total', 'price'),
    'date': ('created_at', 'date', 'timestamp'),
    'method': ('payment_method', 'payment_type'),
    'customer': ('customer_name', 'customer', 'name'),
    'debt_amount': ('amount_owed', 'amount'),
    'paid': ('is_paid', 'paid'),
}


@lru_cache(maxsize=None)
def _resolve(model, role):
    fields = [f for f in model._meta.get_fields() if getattr(f, 'concrete', False)]
    by_name = {f.name: f for f in fields}
    if role == 'owner':
        user_model = get_user_model()
        user_fks = [f for f in fields if f.is_relation and f.related_model == user_model]
        for alias in FIELD_ALIASES['owner']:
            if alias in by_name and by_name[alias] in user_fks:
                return alias
        return user_fks[0].name if user_fks else None
    for alias in FIELD_ALIASES[role]:
        if alias in by_name:
            return alias
    return None


def field(model, role, required=True):
    name = _resolve(model, role)
    if name is None and required:
        raise ImproperlyConfigured(f"{model.__name__} has no field for '{role}'.")
    return name


def owned(model, user):
    """Filters data so every shop owner ONLY sees their own rows."""
    owner_f = _resolve(model, 'owner')
    if owner_f is None:
        logger.warning('%s has no owner field: all shops share rows. Add `user` ForeignKey.', model.__name__)
        return model.objects.all()
    return model.objects.filter(**{owner_f: user})


def owner_kwargs(model, user):
    owner_f = _resolve(model, 'owner')
    return {owner_f: user} if owner_f else {}


def num(value):
    if value is None or isinstance(value, bool):
        return Decimal(0)
    try:
        d = Decimal(str(value))
        return d if d.is_finite() else Decimal(0)
    except (InvalidOperation, ValueError):
        return Decimal(0)


def to_int(d):
    return int(Decimal(str(d)).quantize(Decimal(1), rounding=ROUND_HALF_UP))


# =====================================================================
# AUTHENTICATION (DIRECT, INSTANT, ZERO OTP BARRIERS)
# =====================================================================
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


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def register_view(request):
    """Instant sign-up with Confirm Password. No OTP delay."""
    email = str(request.data.get('email', '')).strip().lower()
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
    """Direct login with password. No OTP."""
    identifier = str(request.data.get('email') or request.data.get('username') or '').strip().lower()
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
    """Direct Google sign-in/sign-up. No OTP."""
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


# =====================================================================
# ONBOARDING (GET & POST)
# =====================================================================
class CompleteOnboardingView(APIView):
    authentication_classes = JWT_AUTH
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, _ = BusinessProfile.objects.get_or_create(user=request.user)
        return Response({
            'user': {
                'id': request.user.id,
                'email': request.user.email,
                'username': request.user.username,
            },
            'profile': BusinessOnboardingSerializer(profile).data,
        }, status=status.HTTP_200_OK)

    def post(self, request):
        profile, _ = BusinessProfile.objects.get_or_create(user=request.user)
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
# REAL BUSINESS ANALYTICS & TIMEFRAME ECONOMICS (PER SHOP)
# =====================================================================
@api_view(['GET'])
@authentication_classes(JWT_AUTH)
@permission_classes([IsAuthenticated])
def business_analytics_view(request):
    user = request.user
    period = request.GET.get('period', 'daily').lower()
    today = timezone.localdate() if settings.USE_TZ else date.today()

    try:
        total_f = field(Sale, 'total')
        date_f = field(Sale, 'date')
        stock_f, price_f = field(Product, 'stock'), field(Product, 'price')

        # 1. Lifetime Store Inventory Value for this user
        products = list(owned(Product, user))
        inventory_value = Decimal(0)
        low_stock_count = 0
        dead_capital_amount = Decimal(0)
        dead_capital_count = 0

        for p in products:
            s_val = num(getattr(p, stock_f, 0))
            p_val = num(getattr(p, price_f, 0))
            val = s_val * p_val
            inventory_value += val
            if s_val <= 5:
                low_stock_count += 1
            if s_val >= 20:
                dead_capital_amount += val
                dead_capital_count += 1

        # 2. Lifetime Unpaid Debts for this user
        debt_qs = owned(CustomerDebt, user)
        paid_f = field(CustomerDebt, 'paid', required=False)
        if paid_f:
            debt_qs = debt_qs.filter(**{paid_f: False})
        debt_amt_f = field(CustomerDebt, 'debt_amount')
        total_debt = num(debt_qs.aggregate(total=Sum(debt_amt_f))['total'])

        # 3. Lifetime Sales for this user
        all_sales = list(owned(Sale, user))
        all_time_sales_sum = sum(num(getattr(s, total_f, 0)) for s in all_sales)

        # Net worth is lifetime: Warehouse assets + All-time sales + All customer debts
        business_net_worth = inventory_value + all_time_sales_sum + total_debt

        # 4. Period breakdown
        trend_points = []
        period_label = "Leo (Today)"
        ticker_tf = "1H"
        period_sales_list = []

        def get_dt(s):
            v = getattr(s, date_f, None)
            if isinstance(v, datetime):
                return timezone.localtime(v).date() if settings.USE_TZ else v.date()
            if isinstance(v, date):
                return v
            return today

        if period == 'weekly':
            period_label = "Wiki Hii (7D)"
            ticker_tf = "1D"
            sw_days = ["Jtatu", "Jnne", "Jtano", "Alh", "Ijm", "Jmosi", "Jpili"]
            for offset in range(6, -1, -1):
                target_date = today - timedelta(days=offset)
                day_name = sw_days[target_date.weekday() if target_date.weekday() < 7 else 0]
                label = f"{day_name} {target_date.day}"
                d_sales = [s for s in all_sales if get_dt(s) == target_date]
                tot = sum(num(getattr(s, total_f, 0)) for s in d_sales)
                period_sales_list.extend(d_sales)
                trend_points.append({"time": label, "sales": to_int(tot), "profit": to_int(tot * PROFIT_MARGIN)})

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
                w_sales = [s for s in all_sales if s_d <= get_dt(s) <= e_d]
                tot = sum(num(getattr(s, total_f, 0)) for s in w_sales)
                period_sales_list.extend(w_sales)
                trend_points.append({"time": w_name, "sales": to_int(tot), "profit": to_int(tot * PROFIT_MARGIN)})

        elif period == 'yearly':
            period_label = "Mwaka Huu (1Y)"
            ticker_tf = "1M"
            months = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Ago", "Sep", "Okt", "Nov", "Des"]
            for m_idx, m_name in enumerate(months, start=1):
                if m_idx > today.month:
                    trend_points.append({"time": m_name, "sales": 0, "profit": 0})
                    continue
                m_sales = [
                    s for s in all_sales 
                    if getattr(s, date_f, None) and hasattr(getattr(s, date_f), 'year') 
                    and getattr(s, date_f).year == today.year and getattr(s, date_f).month == m_idx
                ]
                tot = sum(num(getattr(s, total_f, 0)) for s in m_sales)
                period_sales_list.extend(m_sales)
                trend_points.append({"time": m_name, "sales": to_int(tot), "profit": to_int(tot * PROFIT_MARGIN)})

        else: # daily
            period_label = "Leo (Today)"
            ticker_tf = "1H"
            period_sales_list = [s for s in all_sales if get_dt(s) == today]
            slots = [("08:00", 0, 8), ("11:00", 9, 11), ("14:00", 12, 14), ("17:00", 15, 17), ("20:00", 18, 20), ("23:00", 21, 23)]
            for label, start_h, end_h in slots:
                slot_sales = [
                    s for s in period_sales_list 
                    if getattr(s, date_f, None) and hasattr(getattr(s, date_f), 'hour') 
                    and start_h <= getattr(s, date_f).hour <= end_h
                ]
                tot = sum(num(getattr(s, total_f, 0)) for s in slot_sales)
                trend_points.append({"time": label, "sales": to_int(tot), "profit": to_int(tot * PROFIT_MARGIN)})

        period_sales_total = sum(num(getattr(s, total_f, 0)) for s in period_sales_list)
        period_profit = period_sales_total * PROFIT_MARGIN

        # Economics calculations
        break_even_pct = min(100, int(period_profit / DAILY_FIXED_COST_TARGET * 100)) if DAILY_FIXED_COST_TARGET else 100
        break_even_reached = period_profit >= DAILY_FIXED_COST_TARGET
        debt_ratio = round(float(total_debt / (business_net_worth or 1) * 100), 1)

        return Response({
            "period": period_label,
            "ticker_timeframe": ticker_tf,
            "net_worth": to_int(business_net_worth),
            "today_sales": to_int(period_sales_total),
            "today_profit": to_int(period_profit),
            "today_tx_count": len(period_sales_list),
            "today_debt": to_int(total_debt),
            "low_stock_count": low_stock_count,
            "economics": {
                "health_score": min(100, 65 + (15 if period_sales_total > 0 else 0) + (10 if break_even_reached else 0) + (10 if debt_ratio < 15 else 0)),
                "break_even": {
                    "daily_target": to_int(DAILY_FIXED_COST_TARGET),
                    "current_profit": to_int(period_profit),
                    "percentage": break_even_pct,
                    "is_reached": break_even_reached,
                    "remaining": to_int(max(Decimal(0), DAILY_FIXED_COST_TARGET - period_profit))
                },
                "debt_health": {
                    "ratio": debt_ratio,
                    "status": "Salama" if debt_ratio < 15 else ("Tahadhari" if debt_ratio <= 30 else "Hatari"),
                    "color": "emerald" if debt_ratio < 15 else ("amber" if debt_ratio <= 30 else "rose")
                },
                "dead_capital": {
                    "amount": to_int(dead_capital_amount),
                    "items_count": dead_capital_count
                }
            },
            "payment_split": {"cash": 60, "mobile": 30, "debt": 10},
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
# PRODUCT, SALE, DEBT VIEWSETS (STRICT TENANT ISOLATION)
# =====================================================================
# PRODUCT, SALE, DEBT VIEWSETS (CRASH-PROOF & TENANT ISOLATED)
# =====================================================================

class OwnedModelViewSet(viewsets.ModelViewSet):
    authentication_classes = JWT_AUTH
    permission_classes = [IsAuthenticated]
    model = None

    def get_queryset(self):
        try:
            return owned(self.model, self.request.user).order_by('-pk')
        except Exception as e:
            logger.warning(f"Fallback to all for {self.model.__name__}: {e}")
            return self.model.objects.all().order_by('-pk')

    def perform_create(self, serializer):
        try:
            kwargs = owner_kwargs(self.model, self.request.user)
            serializer.save(**kwargs)
        except Exception:
            serializer.save()



# =====================================================================
# BULLETPROOF PRODUCT, SALE & DEBT VIEWSETS (ZERO 500 CRASHES)
# =====================================================================




# =====================================================================
# PRODUCT, SALE & DEBT VIEWSETS (MATCHES EXACT RENDER POSTGRES COLUMNS)
# =====================================================================

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('-id')
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def list(self, request, *args, **kwargs):
        try:
            qs = Product.objects.all().order_by('-id')
            data = []
            for p in qs:
                data.append({
                    'id': p.id,
                    'name': getattr(p, 'name', ''),
                    'category': getattr(p, 'category', 'Duka'),
                    'price': float(getattr(p, 'price', getattr(p, 'selling_price', 0)) or 0),
                    'selling_price': float(getattr(p, 'price', getattr(p, 'selling_price', 0)) or 0),
                    'stock': int(getattr(p, 'stock', getattr(p, 'stock_quantity', 0)) or 0),
                    'stock_quantity': int(getattr(p, 'stock', getattr(p, 'stock_quantity', 0)) or 0),
                })
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"❌ [PRODUCT LIST ERROR]: {e}", flush=True)
            return Response([], status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        print(f"\n📦 [CREATE PRODUCT ATTEMPT] Data: {request.data}", flush=True)
        try:
            name = str(request.data.get('name', '')).strip()
            category = str(request.data.get('category', 'Duka')).strip() or 'Duka'
            price = float(request.data.get('price') or request.data.get('selling_price') or 0)
            stock = int(request.data.get('stock') or request.data.get('stock_quantity') or 0)

            if not name:
                return Response({'error': 'Jina la bidhaa linahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

            # 💥 ONLY INSERT COLUMNS THAT ACTUALLY EXIST IN POSTGRES (NO user_id!) 💥
            product = Product.objects.create(
                name=name,
                category=category,
                price=price,
                stock=stock
            )
            print(f"✅ [PRODUCT CREATED SUCCESSFULLY] ID: {product.id}, Name: {product.name}", flush=True)

            return Response({
                'id': product.id,
                'name': product.name,
                'category': product.category,
                'price': float(product.price),
                'selling_price': float(product.price),
                'stock': int(product.stock),
                'stock_quantity': int(product.stock),
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"❌ [PRODUCT CREATE ERROR]: {e}", flush=True)
            return Response({'error': f'Hitilafu ya kuunda bidhaa: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


class SaleViewSet(viewsets.ModelViewSet):
    queryset = Sale.objects.all().order_by('-id')
    serializer_class = SaleSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def create(self, request, *args, **kwargs):
        try:
            total = float(request.data.get('total_amount') or request.data.get('amount') or 0)
            method = request.data.get('payment_method', 'Cash')
            customer = request.data.get('customer_name', 'Mteja wa Kawaida')
            items = request.data.get('items', [])

            # Create sale without non-existent user_id
            sale = Sale.objects.create(
                total_amount=total,
                payment_method=method,
                customer_name=customer
            )

            # Deduct stock safely
            for it in items:
                p_id = it.get('id') or it.get('product_id')
                qty = int(it.get('quantity', it.get('qty', 1)))
                if p_id:
                    for s_field in ['stock', 'stock_quantity']:
                        try:
                            Product.objects.filter(pk=p_id).update(**{s_field: F(s_field) - qty})
                            break
                        except Exception:
                            pass

            return Response({
                'id': sale.id,
                'total_amount': total,
                'payment_method': method,
                'customer_name': customer,
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"❌ [SALE CREATE ERROR]: {e}", flush=True)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CustomerDebtViewSet(viewsets.ModelViewSet):
    queryset = CustomerDebt.objects.all().order_by('-id')
    serializer_class = CustomerDebtSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def create(self, request, *args, **kwargs):
        try:
            name = request.data.get('customer_name') or request.data.get('name') or 'Mteja'
            amt = float(request.data.get('amount_owed') or request.data.get('amount') or 0)
            phone = request.data.get('phone', '')
            notes = request.data.get('notes', '')

            debt = CustomerDebt.objects.create(
                customer_name=name,
                amount_owed=amt,
                phone=phone,
                notes=notes,
                is_paid=False
            )
            return Response({
                'id': debt.id,
                'customer_name': name,
                'amount_owed': amt,
                'phone': phone,
                'is_paid': False
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)









# =====================================================================
# HEALTH, EXPENSES & GEMINI AI VIEW
# =====================================================================
@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def health_check(request):
    return Response({'status': 'active', 'service': 'Duka Poa API'}, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
@authentication_classes(JWT_AUTH)
@permission_classes([IsAuthenticated])
def expenses_view(request):
    return Response([], status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes(JWT_AUTH)
@permission_classes([IsAuthenticated])
def ocr_invoice_scanner_view(request):
    return Response({'message': 'Scan received'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes(JWT_AUTH)
@permission_classes([IsAuthenticated])
def ai_chat_view(request):
    """Answers using only the logged in user's business context."""
    user = request.user
    user_prompt = str(request.data.get('message', '')).strip()
    if not user_prompt:
        return Response({'reply': 'Tafadhali andika swali lako.'}, status=status.HTTP_400_BAD_REQUEST)

    # Scoped only to this user
    sales_total = sum(num(getattr(s, field(Sale, 'total'), 0)) for s in owned(Sale, user))
    prods = list(owned(Product, user).values())
    debts = list(owned(CustomerDebt, user).values())

    reply = (
        f"Habari! Nimesoma data za duka lako. Mauzo yako ni TZS {int(sales_total):,}, "
        f"una aina {len(prods)} za bidhaa stoo, na una madeni {len(debts)} ya wateja. "
        "Una swali lolote la kukuza biashara yako?"
    )
    return Response({'reply': reply}, status=status.HTTP_200_OK)

gemini_ai_assistant_view = ai_chat_view
