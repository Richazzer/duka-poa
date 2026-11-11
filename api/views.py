"""
Duka Poa API: views.py

Multi-tenant: every shop owner only ever sees and changes their own data.
Flexible: model field names are auto-detected (see FIELD_ALIASES), so this
works with `selling_price` or `price`, `stock` or `stock_quantity`, etc.

Environment variables (Render -> Environment):
    GOOGLE_CLIENT_ID          Google OAuth client id (verifies Google sign-in)
    GEMINI_API_KEY            Gemini key for the AI agent
    GEMINI_MODEL              optional, default gemini-2.5-flash
    ESTIMATED_PROFIT_MARGIN   optional, default 0.22
    DAILY_FIXED_COST_TARGET   optional, default 20000
"""
import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, time as dtime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Q, Sum
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import BusinessProfile, CustomerDebt, Product, Sale
from .serializers import (
    BusinessOnboardingSerializer,
    CustomerDebtSerializer,
    ProductSerializer,
    SaleSerializer,
)

logger = logging.getLogger(__name__)

# =====================================================================
# SETTINGS & CONSTANTS
# =====================================================================
JWT_AUTH = [JWTAuthentication]

LOW_STOCK_LIMIT = 5
DEAD_STOCK_THRESHOLD = 20

PROFIT_MARGIN = Decimal(os.environ.get('ESTIMATED_PROFIT_MARGIN', '0.22'))
DAILY_FIXED_COST_TARGET = Decimal(os.environ.get('DAILY_FIXED_COST_TARGET', '20000'))

PERIODS = ('daily', 'weekly', 'monthly', 'yearly')
PERIOD_LABELS = {
    'daily': 'Leo (Today)',
    'weekly': 'Wiki Hii (7D)',
    'monthly': 'Mwezi Huu (30D)',
    'yearly': 'Mwaka Huu (1Y)',
}
PERIOD_TIMEFRAMES = {'daily': '1H', 'weekly': '1D', 'monthly': '1W', 'yearly': '1M'}

DAILY_SLOTS = (
    ('08:00', 0, 8), ('11:00', 9, 11), ('14:00', 12, 14),
    ('17:00', 15, 17), ('20:00', 18, 20), ('23:00', 21, 23),
)
SW_DAYS = ('Jtatu', 'Jnne', 'Jtano', 'Alh', 'Ijm', 'Jmosi', 'Jpili')
SW_MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Ago', 'Sep', 'Okt', 'Nov', 'Des')

# =====================================================================
# FLEXIBLE FIELD RESOLVER
# Add your own field names to a tuple if your models use something else.
# =====================================================================
FIELD_ALIASES = {
    'owner': ('user', 'owner', 'shop', 'business', 'created_by'),
    'name': ('name', 'title'),
    'price': ('selling_price', 'price'),
    'cost': ('buying_price', 'cost_price', 'purchase_price', 'cost'),
    'stock': ('stock', 'stock_quantity', 'quantity'),
    'total': ('total_amount', 'amount', 'total', 'price'),
    'date': ('created_at', 'date', 'timestamp'),
    'method': ('payment_method', 'payment_type'),
    'customer': ('customer_name', 'customer', 'name'),
    'debt_amount': ('amount_owed', 'amount'),
    'paid': ('is_paid', 'paid'),
}

INTEGER_TYPES = {
    'IntegerField', 'BigIntegerField', 'SmallIntegerField',
    'PositiveIntegerField', 'PositiveBigIntegerField', 'PositiveSmallIntegerField',
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
        raise ImproperlyConfigured(
            f"{model.__name__} has no field for '{role}'. "
            f"Looked for: {', '.join(FIELD_ALIASES[role])}."
        )
    return name


_warned_models = set()


def owned(model, user):
    """
    Queryset limited to the logged-in shop owner's rows.

    If the model has no owner field yet (no `user` foreign key), the app keeps working but
    every shop shares the same rows. Add the field (see README steps) to separate shops.
    Set STRICT_TENANT_ISOLATION=1 to refuse to run without it.
    """
    owner_f = _resolve(model, 'owner')
    if owner_f is None:
        if os.environ.get('STRICT_TENANT_ISOLATION') == '1':
            raise ImproperlyConfigured(
                f"{model.__name__} has no owner field (a ForeignKey to the user model)."
            )
        if model not in _warned_models:
            _warned_models.add(model)
            logger.warning(
                '%s has no owner field: all shops share these rows. Add a `user` ForeignKey.',
                model.__name__,
            )
        return model.objects.all()
    return model.objects.filter(**{owner_f: user})


def owner_kwargs(model, user):
    """Extra kwargs for serializer.save() so new rows belong to the logged-in user."""
    owner_f = _resolve(model, 'owner')
    return {owner_f: user} if owner_f else {}


def _internal_type(model, name):
    return model._meta.get_field(name).get_internal_type()


# =====================================================================
# SMALL HELPERS
# =====================================================================
class ApiError(Exception):
    def __init__(self, message, status_code=status.HTTP_400_BAD_REQUEST):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def to_decimal(value, default=None):
    if value is None or isinstance(value, bool):
        return default
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return default
    return d if d.is_finite() else default


def num(value):
    return to_decimal(value, Decimal(0))


def as_number(d):
    """Decimal -> int when whole, else float (safe for Integer/Float/Decimal serializer fields)."""
    return int(d) if d == d.to_integral_value() else float(d)


def to_int(d):
    return int(d.quantize(Decimal(1), rounding=ROUND_HALF_UP))


def coerce_like(current, value):
    """Return `value` in the same numeric type as `current` (int stays int, float stays float)."""
    if isinstance(current, bool):
        return value
    if isinstance(current, int):
        return int(value)
    if isinstance(current, float):
        return float(value)
    return value


def client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def rate_limited(key, limit, window_seconds):
    """True when `key` was used more than `limit` times inside the window."""
    cache_key = f'duka-rl:{key}'
    cache.add(cache_key, 0, timeout=window_seconds)
    try:
        count = cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 1, timeout=window_seconds)
        count = 1
    return count > limit


def _today():
    return timezone.localdate() if settings.USE_TZ else date.today()


def _local_dt(value):
    if isinstance(value, datetime):
        if settings.USE_TZ and timezone.is_aware(value):
            return timezone.localtime(value)
        return value
    return None


def _range_start(model, date_field, day):
    """Start of `day` in the right type for the model's date field."""
    if _internal_type(model, date_field) == 'DateField':
        return day
    start = datetime.combine(day, dtime.min)
    return timezone.make_aware(start) if settings.USE_TZ else start


def _requested_timezone(name):
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None


# =====================================================================
# AUTHENTICATION (instant sign-up and sign-in, no OTP)
# =====================================================================
PASSWORD_MIN_LENGTH = 6


def _auth_payload(user, message, **extra):
    profile, _ = BusinessProfile.objects.get_or_create(user=user)
    refresh = RefreshToken.for_user(user)
    payload = {
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
    payload.update(extra)
    return payload


def _find_user(identifier):
    User = get_user_model()
    return User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def register_view(request):
    """Create an account with email + password (+ optional confirm_password). Logs the user in."""
    email = str(request.data.get('email') or '').strip().lower()
    password = request.data.get('password')
    confirm = request.data.get('confirm_password', request.data.get('confirmPassword'))

    if not email or not password:
        return Response({'error': 'Barua pepe na nenosiri vinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_email(email)
        if len(email) > 150:
            raise DjangoValidationError('too long')
    except DjangoValidationError:
        return Response({'error': 'Barua pepe si sahihi.'}, status=status.HTTP_400_BAD_REQUEST)

    password = str(password)
    if len(password) < PASSWORD_MIN_LENGTH:
        return Response(
            {'error': f'Nenosiri linapaswa kuwa na angalau herufi au tarakimu {PASSWORD_MIN_LENGTH}.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if confirm is not None and str(confirm) != password:
        return Response({'error': 'Nenosiri halifanani. Tafadhali thibitisha tena.'}, status=status.HTTP_400_BAD_REQUEST)

    if rate_limited(f'register-ip:{client_ip(request)}', limit=15, window_seconds=3600):
        return Response(
            {'error': 'Umejaribu mara nyingi sana. Subiri kidogo kisha jaribu tena.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    if _find_user(email):
        return Response(
            {'error': 'Barua pepe hii tayari imesajiliwa. Tafadhali ingia.'}, status=status.HTTP_400_BAD_REQUEST
        )

    User = get_user_model()
    try:
        with transaction.atomic():
            user = User.objects.create_user(username=email, email=email, password=password)
            BusinessProfile.objects.get_or_create(user=user, defaults={'is_onboarded': False})
    except IntegrityError:  # two requests with the same email raced
        return Response(
            {'error': 'Barua pepe hii tayari imesajiliwa. Tafadhali ingia.'}, status=status.HTTP_400_BAD_REQUEST
        )

    return Response(_auth_payload(user, 'Usajili umekamilika kikamilifu!'), status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def login_view(request):
    identifier = str(request.data.get('email') or request.data.get('username') or '').strip()
    password = request.data.get('password')

    if not identifier or not password:
        return Response({'error': 'Barua pepe na nenosiri vinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    if rate_limited(f'login:{client_ip(request)}:{identifier.lower()}', limit=10, window_seconds=900):
        return Response(
            {'error': 'Umejaribu mara nyingi sana. Subiri dakika chache kisha jaribu tena.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    user = _find_user(identifier)
    if not user:
        return Response({'error': 'Akaunti hii haipo. Tafadhali jisajili kwanza.'}, status=status.HTTP_400_BAD_REQUEST)

    if not user.is_active:
        return Response({'error': 'Akaunti hii imezimwa.'}, status=status.HTTP_403_FORBIDDEN)

    # SECURITY: never set a password here. Anyone could take over a Google account that way.
    if not user.has_usable_password():
        return Response(
            {'error': 'Akaunti hii ilisajiliwa kwa Google. Tumia "Continue with Google" kuingia.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not user.check_password(password):
        return Response({'error': 'Nenosiri au barua pepe si sahihi.'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(_auth_payload(user, 'Umeingia kwa mafanikio!'), status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def refresh_token_view(request):
    """Exchange a refresh token for a new access token (keeps users logged in)."""
    token = request.data.get('refresh_token') or request.data.get('refresh')
    if not token:
        return Response({'error': 'Refresh token inahitajika.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        refresh = RefreshToken(token)
        User = get_user_model()
        if not User.objects.filter(pk=refresh.get('user_id'), is_active=True).exists():
            raise TokenError('inactive user')
        return Response({'access_token': str(refresh.access_token)}, status=status.HTTP_200_OK)
    except TokenError:
        return Response({'error': 'Kipindi chako kimeisha. Ingia tena.'}, status=status.HTTP_401_UNAUTHORIZED)


def _verify_google_token(credential):
    url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + urllib.parse.quote(credential, safe='')
    with urllib.request.urlopen(urllib.request.Request(url), timeout=6) as resp:
        data = json.loads(resp.read().decode('utf-8'))

    expected_aud = os.environ.get('GOOGLE_CLIENT_ID', '').strip()
    if expected_aud:
        if data.get('aud') != expected_aud:
            raise ValueError('Google token audience mismatch')
    else:
        logger.warning('GOOGLE_CLIENT_ID is not set: Google token audience is NOT being verified')

    if str(data.get('email_verified', '')).lower() != 'true':
        raise ValueError('Google email not verified')
    return (data.get('email') or '').strip().lower()


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def google_auth_view(request):
    """Google sign-in and sign-up in one step: creates the account the first time."""
    credential = request.data.get('credential')
    if not credential:
        return Response({'error': 'Token ya Google inahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        email = _verify_google_token(str(credential))
    except (urllib.error.URLError, socket.timeout, TimeoutError):
        return Response(
            {'error': 'Imeshindikana kuwasiliana na Google. Jaribu tena.'},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    except (ValueError, json.JSONDecodeError):
        return Response({'error': 'Token ya Google si sahihi.'}, status=status.HTTP_400_BAD_REQUEST)

    if not email:
        return Response({'error': 'Barua pepe haijapatikana kutoka Google.'}, status=status.HTTP_400_BAD_REQUEST)

    user = _find_user(email)
    if not user:
        User = get_user_model()
        try:
            user = User.objects.create(username=email, email=email)
            user.set_unusable_password()
            user.save(update_fields=['password'])
        except IntegrityError:
            user = _find_user(email)

    if not user or not user.is_active:
        return Response({'error': 'Akaunti hii imezimwa.'}, status=status.HTTP_403_FORBIDDEN)

    return Response(_auth_payload(user, 'Umeingia kwa Google kwa mafanikio!'), status=status.HTTP_200_OK)


# =====================================================================
# ONBOARDING
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
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
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
# ANALYTICS (per shop, aggregated from the database, timezone-aware)
# =====================================================================
def _period_config(period, today):
    """Returns (label, timeframe, start_day, bucket_labels, bucket_of(day, hour) -> index|None)."""
    label, timeframe = PERIOD_LABELS[period], PERIOD_TIMEFRAMES[period]

    if period == 'daily':
        labels = [slot[0] for slot in DAILY_SLOTS]

        def bucket_of(day, hour):
            if day != today:
                return None
            for i, (_, low, high) in enumerate(DAILY_SLOTS):
                if low <= hour <= high:
                    return i
            return None

        return label, timeframe, today, labels, bucket_of

    if period == 'weekly':
        days = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
        labels = [f'{SW_DAYS[d.weekday()]} {d.day}' for d in days]
        index = {d: i for i, d in enumerate(days)}
        return label, timeframe, days[0], labels, lambda day, hour: index.get(day)

    if period == 'monthly':
        # 30 days in 4 buckets: Wiki 4 = last 7 days, Wiki 3 = 7-13, Wiki 2 = 14-20, Wiki 1 = 21-29 days ago.
        def bucket_of(day, hour):
            days_ago = (today - day).days
            if not 0 <= days_ago <= 29:
                return None
            return 3 - min(3, days_ago // 7)

        return label, timeframe, today - timedelta(days=29), [f'Wiki {n}' for n in range(1, 5)], bucket_of

    def bucket_of(day, hour):  # yearly: calendar year up to today
        if day.year != today.year or day > today:
            return None
        return day.month - 1

    return label, timeframe, date(today.year, 1, 1), list(SW_MONTHS), bucket_of


def _payment_group(method):
    m = str(method o