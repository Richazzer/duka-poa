from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    health_check,
    register_view,
    login_view,
    google_auth_view,
    CompleteOnboardingView,
    business_analytics_view,
    ProductViewSet,
    SaleViewSet,
    CustomerDebtViewSet,
    expenses_view,
    ocr_invoice_scanner_view,
    ai_chat_view,
)

router = DefaultRouter()
router.register(r'products', ProductViewSet, basename='product')
router.register(r'sales', SaleViewSet, basename='sale')
router.register(r'debts', CustomerDebtViewSet, basename='debt')

urlpatterns = [
    # Health Check for UptimeRobot / Cron-Job
    path('health/', health_check, name='health-check'),

    # Direct Authentication (No OTP delays)
    path('auth/register/', register_view, name='register'),
    path('auth/login/', login_view, name='login'),
    path('auth/google/', google_auth_view, name='google-auth'),

    # Onboarding
    path('onboarding/', CompleteOnboardingView.as_view(), name='complete-onboarding'),

    # Real Analytics & Economics
    path('analytics/economics/', business_analytics_view, name='business-economics'),

    # AI Business Agent
    path('ai/chat/', ai_chat_view, name='ai-chat'),

    # Core Router (products, sales, debts)
    path('', include(router.urls)),

    # Extras
    path('expenses/', expenses_view, name='expenses'),
    path('ocr/scan/', ocr_invoice_scanner_view, name='ocr-scan'),
]
