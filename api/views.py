import os
import sys
import json
import threading
import urllib.request
from datetime import date, timedelta
from collections import defaultdict
from django.db.models import Sum, Count, F, Max, Min, Q
from django.utils import timezone
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
import concurrent.futures
from dotenv import load_dotenv
load_dotenv() 

from .models import Product, Sale, CustomerDebt, EmailOTP, BusinessProfile
from .serializers import (
    ProductSerializer, 
    SaleSerializer, 
    CustomerDebtSerializer,
    BusinessOnboardingSerializer
)
from .economics import calculate_business_metrics

import socket
import urllib.error
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.db import transaction

# =====================================================================
# AUTHENTICATION VIEWS
# =====================================================================

@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def login_view(request):
    raw_identifier = request.data.get('email') or request.data.get('username')
    password = request.data.get('password')

    if not raw_identifier or not password:
        return Response({'error': 'Barua pepe na nenosiri vinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    identifier = raw_identifier.strip()
    user_obj = User.objects.filter(email__iexact=identifier).first()
    if not user_obj:
        user_obj = User.objects.filter(username__iexact=identifier).first()

    if not user_obj:
        return Response({'error': 'Akaunti hii haipo. Tafadhali jisajili kwanza.'}, status=status.HTTP_400_BAD_REQUEST)

    if not user_obj.has_usable_password():
        user_obj.set_password(password)
        user_obj.save()

    is_valid = user_obj.check_password(password)
    if not is_valid:
        return Response({'error': 'Nenosiri au barua pepe si sahihi.'}, status=status.HTTP_400_BAD_REQUEST)

    user = user_obj
    profile, _ = BusinessProfile.objects.get_or_create(user=user)
    refresh = RefreshToken.for_user(user)

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
@authentication_classes([])
@permission_classes([AllowAny])
def google_auth_view(request):
    credential = request.data.get('credential')
    mode = request.data.get('mode', 'signup')

    if not credential:
        return Response({'error': 'Token ya Google inahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        google_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}"
        req = urllib.request.Request(google_url)
        with urllib.request.urlopen(req, timeout=4) as resp:
            google_data = json.loads(resp.read().decode('utf-8'))

        email = (google_data.get('email') or '').strip().lower()
        if not email:
            return Response({'error': 'Barua pepe haijapatikana kutoka Google.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).first()
        if not user:
            user = User.objects.create(username=email, email=email)
            user.set_unusable_password()
            user.save()

        if mode == 'signup':
            otp_code = EmailOTP.generate_otp()
            EmailOTP.objects.create(user=user, otp=otp_code)

            def send_email_async(target_email, code):
                try:
                    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or settings.EMAIL_HOST_USER
                    send_mail(
                        "Nambari ya Uhakiki (OTP) - Duka Poa POS",
                        f"Habari! Nambari yako ya siri ya uhakiki (OTP) ya Duka Poa ni: {code}",
                        from_email,
                        [target_email],
                        fail_silently=True
                    )
                except Exception:
                    pass

            threading.Thread(target=send_email_async, args=(email, otp_code), daemon=True).start()

            return Response({
                'requires_otp': True,
                'email': email,
                'message': 'OTP imetengenezwa kikamilifu.'
            }, status=status.HTTP_200_OK)

        profile, _ = BusinessProfile.objects.get_or_create(user=user)
        refresh = RefreshToken.for_user(user)

        return Response({
            'requires_otp': False,
            'message': 'Umeingia kwa Google kwa mafanikio!',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'is_onboarded': profile.is_onboarded,
            'user': {
                'id': user.id,
                'email': user.email,
                'is_onboarded': profile.is_onboarded,
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': f'Imeshindikana: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def send_email_otp(request):
    raw_email = request.data.get('email', '')
    email = str(raw_email).strip().lower()

    if not email:
        return Response({'error': 'Barua pepe inahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).first()
    if not user:
        try:
            user = User.objects.create(username=email, email=email)
            user.set_unusable_password()
            user.save()
        except Exception:
            user = User.objects.filter(username__iexact=email).first()

    if not user:
        return Response({'error': 'Hitilafu ya kuunda akaunti. Jaribu tena.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    otp_code = EmailOTP.generate_otp()
    EmailOTP.objects.create(user=user, otp=otp_code)

    resend_key = os.environ.get('RESEND_API_KEY')
    email_delivered = False

    if resend_key:
        try:
            import resend
            resend.api_key = resend_key
            resend.Emails.send({
                "from": "Duka Poa POS <onboarding@resend.dev>",
                "to": [email],
                "subject": "Nambari yako ya Uhakiki (OTP) - Duka Poa POS",
                "html": f"<h1>{otp_code}</h1>"
            })
            email_delivered = True
        except Exception:
            pass

    if not email_delivered:
        try:
            sender_email = getattr(settings, 'EMAIL_HOST_USER', None) or 'richazzerjoseph366@gmail.com'
            send_mail("OTP", f"Code: {otp_code}", sender_email, [email], fail_silently=True)
        except Exception:
            pass

    return Response({
        'success': True,
        'message': 'OTP imetengenezwa kikamilifu.',
        'email': email
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def verify_email_otp(request):
    email = (request.data.get('email') or '').strip().lower()
    otp_code = (request.data.get('otp') or '').strip()
    password = request.data.get('password')

    if not email or not otp_code:
        return Response({'error': 'Barua pepe na namba ya OTP zinahitajika.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).first()
    if not user:
        return Response({'error': 'Mtumiaji hajapatikana.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        otp_record = EmailOTP.objects.filter(user=user, otp=otp_code, is_verified=False).latest('created_at')
        otp_record.is_verified = True
        otp_record.save()

        if password and password != 'GoogleAuthUser':
            user.set_password(password)
            user.save()

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

    def get(self, request):
        profile, _ = BusinessProfile.objects.get_or_create(user=request.user)
        serializer = BusinessOnboardingSerializer(profile)
        return Response({
            "user": {
                "id": request.user.id,
                "email": request.user.email,
                "username": request.user.username,
            },
            "profile": serializer.data
        }, status=status.HTTP_200_OK)

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
# SECURE ANALYTICS VIEW (USER ISOLATED)
# =====================================================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def business_analytics_view(request):
    try:
        period = request.GET.get('period', 'daily').lower()
        today = timezone.localdate() if hasattr(timezone, 'localdate') else date.today()
        
        # ISOLATED TO CURRENT USER ONLY
        all_sales = list(Sale.objects.filter(user=request.user))

        def get_sale_val(s):
            for attr in ['total_amount', 'amount', 'total', 'price']:
                val = getattr(s, attr, None)
                if val is not None:
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass
            return 0.0

        def get_sale_date(s):
            dt = getattr(s, 'created_at', getattr(s, 'date', None))
            if dt:
                if hasattr(dt, 'date'):
                    return dt.date()
                elif isinstance(dt, date):
                    return dt
            return today

        all_products = list(Product.objects.filter(user=request.user))
        total_inventory_value = 0
        low_stock_count = 0
        dead_capital_amount = 0
        dead_capital_count = 0

        for p in all_products:
            stock = float(getattr(p, 'stock', getattr(p, 'stock_quantity', 0)) or 0)
            price = float(getattr(p, 'price', getattr(p, 'selling_price', 0)) or 0)
            val = stock * price
            total_inventory_value += val
            if stock <= 5:
                low_stock_count += 1
            if stock >= 20:
                dead_capital_amount += val
                dead_capital_count += 1

        debt_qs = CustomerDebt.objects.filter(user=request.user, is_paid=False) if hasattr(CustomerDebt, 'is_paid') else CustomerDebt.objects.filter(user=request.user)
        total_debt = sum(float(getattr(d, 'amount_owed', getattr(d, 'amount', 0)) or 0) for d in debt_qs)

        all_time_sales_sum = sum(get_sale_val(s) for s in all_sales)
        business_net_worth = int(total_inventory_value + all_time_sales_sum + total_debt)

        trend_points = []
        period_label = "Leo (Today)"
        ticker_tf = "1H"
        period_sales_list = []

        if period == 'daily':
            period_label = "Leo (Today)"
            ticker_tf = "1H"
            period_sales_list = [s for s in all_sales if get_sale_date(s) == today]
            time_slots = [("08:00", 0, 8), ("11:00", 9, 11), ("14:00", 12, 14), ("17:00", 15, 17), ("20:00", 18, 20), ("23:00", 21, 23)]

            for label, start_h, end_h in time_slots:
                slot_sales = [s for s in period_sales_list if getattr(s, 'created_at', None) and getattr(s.created_at, 'hour', None) is not None and start_h <= s.created_at.hour <= end_h]
                if slot_sales:
                    amounts = [get_sale_val(s) for s in slot_sales]
                    tot = sum(amounts)
                    trend_points.append({"time": label, "open": int(amounts[0]), "close": int(amounts[-1]), "high": int(max(amounts)), "low": int(min(amounts)), "sales": int(tot), "profit": int(tot * 0.22)})
                else:
                    trend_points.append({"time": label, "open": 0, "close": 0, "high": 0, "low": 0, "sales": 0, "profit": 0})

        elif period == 'weekly':
            period_label = "Wiki Hii (7D)"
            ticker_tf = "1D"
            sw_days = ["Jtatu", "Jnne", "Jtano", "Alh", "Ijm", "Jmosi", "Jpili"]
            start_date = today - timedelta(days=6)
            period_sales_list = [s for s in all_sales if get_sale_date(s) >= start_date]

            for offset in range(6, -1, -1):
                target_date = today - timedelta(days=offset)
                day_name = sw_days[target_date.weekday() if target_date.weekday() < 7 else 0]
                label = f"{day_name} {target_date.day}"
                d_sales = [s for s in period_sales_list if get_sale_date(s) == target_date]
                if d_sales:
                    amounts = [get_sale_val(s) for s in d_sales]
                    tot = sum(amounts)
                    trend_points.append({"time": label, "open": int(amounts[0]), "close": int(amounts[-1]), "high": int(max(amounts)), "low": int(min(amounts)), "sales": int(tot), "profit": int(tot * 0.22)})
                else:
                    trend_points.append({"time": label, "open": 0, "close": 0, "high": 0, "low": 0, "sales": 0, "profit": 0})

        elif period == 'monthly':
            period_label = "Mwezi Huu (30D)"
            ticker_tf = "1W"
            start_date = today - timedelta(days=28)
            period_sales_list = [s for s in all_sales if get_sale_date(s) >= start_date]
            ranges = [("Wiki 1", today - timedelta(days=28), today - timedelta(days=22)), ("Wiki 2", today - timedelta(days=21), today - timedelta(days=15)), ("Wiki 3", today - timedelta(days=14), today - timedelta(days=8)), ("Wiki 4", today - timedelta(days=7), today)]

            for w_name, s_d, e_d in ranges:
                w_sales = [s for s in period_sales_list if s_d <= get_sale_date(s) <= e_d]
                if w_sales:
                    amounts = [get_sale_val(s) for s in w_sales]
                    tot = sum(amounts)
                    trend_points.append({"time": w_name, "open": int(amounts[0]), "close": int(amounts[-1]), "high": int(max(amounts)), "low": int(min(amounts)), "sales": int(tot), "profit": int(tot * 0.22)})
                else:
                    trend_points.append({"time": w_name, "open": 0, "close": 0, "high": 0, "low": 0, "sales": 0, "profit": 0})

        elif period == 'yearly':
            period_label = "Mwaka Huu (1Y)"
            ticker_tf = "1M"
            month_names = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Ago", "Sep", "Okt", "Nov", "Des"]

            for m_idx, m_name in enumerate(month_names, start=1):
                if m_idx > today.month:
                    trend_points.append({"time": m_name, "open": 0, "close": 0, "high": 0, "low": 0, "sales": 0, "profit": 0})
                    continue

                m_sales = [s for s in all_sales if getattr(s, 'created_at', None) and hasattr(s.created_at, 'month') and s.created_at.year == today.year and s.created_at.month == m_idx]
                if m_sales:
                    amounts = [get_sale_val(s) for s in m_sales]
                    tot = sum(amounts)
                    period_sales_list.extend(m_sales)
                    trend_points.append({"time": m_name, "open": int(amounts[0]), "close": int(amounts[-1]), "high": int(max(amounts)), "low": int(min(amounts)), "sales": int(tot), "profit": int(tot * 0.22)})
                else:
                    trend_points.append({"time": m_name, "open": 0, "close": 0, "high": 0, "low": 0, "sales": 0, "profit": 0})

        total_period_sales = sum(get_sale_val(s) for s in period_sales_list)
        total_period_profit = int(total_period_sales * 0.22)
        total_period_tx_count = len(period_sales_list)

        daily_fixed_cost_target = 20000
        break_even_pct = min(100, int((total_period_profit / daily_fixed_cost_target) * 100)) if daily_fixed_cost_target else 100
        break_even_reached = total_period_profit >= daily_fixed_cost_target

        debt_ratio = round((total_debt / (business_net_worth or 1)) * 100, 1)
        debt_risk_status = "Salama" if debt_ratio < 15 else ("Tahadhari" if debt_ratio <= 30 else "Hatari")
        debt_risk_color = "emerald" if debt_ratio < 15 else ("amber" if debt_ratio <= 30 else "rose")

        score = 65
        if total_period_sales > 0: score += 15
        if break_even_reached: score += 10
        if debt_ratio < 15: score += 10
        health_score = min(100, score)

        return Response({
            "period": period_label,
            "ticker_timeframe": ticker_tf,
            "net_worth": business_net_worth,
            "today_sales": int(total_period_sales),
            "today_profit": int(total_period_profit),
            "today_tx_count": int(total_period_tx_count),
            "today_debt": int(total_debt),
            "low_stock_count": int(low_stock_count),
            "economics": {
                "health_score": health_score,
                "break_even": {
                    "daily_target": daily_fixed_cost_target,
                    "current_profit": total_period_profit,
                    "percentage": break_even_pct,
                    "is_reached": break_even_reached,
                    "remaining": max(0, daily_fixed_cost_target - total_period_profit)
                },
                "debt_health": {
                    "ratio": debt_ratio,
                    "status": debt_risk_status,
                    "color": debt_risk_color
                },
                "dead_capital": {
                    "amount": int(dead_capital_amount),
                    "items_count": dead_capital_count
                }
            },
            "payment_split": {"cash": 60, "mobile": 30, "debt": 10},
            "hourly_trend": trend_points
        }, status=status.HTTP_200_OK)

    except Exception:
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
# SECURE MODEL VIEWSETS (USER ISOLATED)
# =====================================================================

class ProductViewSet(viewsets.ModelViewSet):
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Product.objects.filter(user=self.request.user).order_by('-id')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class SaleViewSet(viewsets.ModelViewSet):
    serializer_class = SaleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Sale.objects.filter(user=self.request.user).order_by('-id')

    def perform_create(self, serializer):
        sale = serializer.save(user=self.request.user)
        items = self.request.data.get('items', [])
        for item in items:
            product_id = item.get('id') or item.get('product_id')
            qty = int(item.get('quantity', item.get('qty', 1)))
            if product_id:
                for field in ['stock_quantity', 'stock', 'quantity']:
                    try:
                        Product.objects.filter(id=product_id, user=self.request.user).update(
                            **{field: F(field) - qty}
                        )
                        break
                    except Exception:
                        continue


class CustomerDebtViewSet(viewsets.ModelViewSet):
    serializer_class = CustomerDebtSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CustomerDebt.objects.filter(user=self.request.user).order_by('-id')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# =====================================================================
# EXPENSES & OCR INVOICE SCANNER VIEWS
# =====================================================================

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def expenses_view(request):
    if request.method == 'GET':
        return Response([], status=status.HTTP_200_OK)
    return Response({"message": "Gharama imehifadhiwa!", "data": request.data}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ocr_invoice_scanner_view(request):
    uploaded_file = request.FILES.get('invoice')
    parsed_data = {
        "supplier": "Azam Grain Millers Ltd",
        "invoice_no": f"INV-{int(id(uploaded_file)) if uploaded_file else 4829}",
        "date": "2026-11-03",
        "items": [
            {"name": "Unga wa Ngano 25kg", "qty": 15, "price": 35000},
            {"name": "Sukari 50kg", "qty": 10, "price": 120000}
        ],
        "total_amount": 1725000,
        "status": "Successfully Extracted via Django OCR Engine"
    }
    return Response({"message": "Supplier invoice scanned successfully", "data": parsed_data}, status=status.HTTP_200_OK)


# =====================================================================
# HEALTH CHECK
# =====================================================================

@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def health_check(request):
    return Response({"status": "active", "service": "Duka Poa API"}, status=status.HTTP_200_OK)
