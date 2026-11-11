from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    health_check,
    register_view,
    login_view,
    google_auth_view,
    send_email_otp,
    verify_email_otp,
    CompleteOnboardingView,
    business_analytics_view,
    ProductViewSet,
    SaleViewSet,
    CustomerDebtViewSet,
    expenses_view,
    ocr_invoice_scanner_view,
    gemini_ai_assistant_view,
)

router = DefaultRouter()
router.register(r'products', ProductViewSet, basename='product')
router.register(r'sales', SaleViewSet, basename='sale')
router.register(r'debts', CustomerDebtViewSet, basename='debt')

urlpatterns = [
    path('health/', health_check, name='health-check'),
    path('auth/register/', register_view, name='register'),
    path('auth/login/', login_view, name='login'),
    path('auth/google/', google_auth_view, name='google-auth'),
    path('auth/send-otp/', send_email_otp, name='send-otp'),
    path('auth/verify-otp/', verify_email_otp, name='verify-otp'),
    path('onboarding/', CompleteOnboardingView.as_view(), name='complete-onboarding'),
    path('analytics/economics/', business_analytics_view, name='business-economics'),
    path('ai/chat/', gemini_ai_assistant_view, name='ai-chat'),
    path('', include(router.urls)),
    path('expenses/', expenses_view, name='expenses'),
    path('ocr/scan/', ocr_invoice_scanner_view, name='ocr-scan'),
]
