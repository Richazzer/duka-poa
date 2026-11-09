from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

from .views import (
    login_view,
    send_email_otp,
    verify_email_otp,
    CompleteOnboardingView,
    business_analytics_view,
    ocr_invoice_scanner_view,
    ProductViewSet,
    SaleViewSet,
    CustomerDebtViewSet,
    expenses_view,
    gemini_ai_assistant_view,
    google_auth_view,
    health_check
)

router = DefaultRouter()
router.register(r'products', ProductViewSet)
router.register(r'sales', SaleViewSet)
router.register(r'debts', CustomerDebtViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('health/', health_check, name='health-check'),
    path('auth/google/', google_auth_view, name='google-auth'),
    path('auth/send-otp/', send_email_otp, name='send-otp'),
    path('auth/verify-otp/', verify_email_otp, name='verify-otp'),
    path('auth/login/', login_view, name='login'),
   
    path('expenses/', expenses_view, name='expenses'), 
    path('ocr/scan/', ocr_invoice_scanner_view, name='ocr-scan'),
    
    
    
    # Economics & Analytics
    path('analytics/economics/', business_analytics_view, name='business-economics'),
    
    path('ai/chat/', gemini_ai_assistant_view, name='ai-chat'),
    path('ai/chat/',  ai_chat_view),
    path('ai/apply/', ai_apply_view),
    # Auth Endpoints
    
   
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout/', TokenBlacklistView.as_view(), name='token_blacklist'),
    
    # Onboarding
    path('onboarding/', CompleteOnboardingView.as_view(), name='complete-onboarding'),
]
