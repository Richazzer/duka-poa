from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api.views import (
    ProductViewSet, SaleViewSet, CustomerDebtViewSet, 
    ocr_invoice_scanner_view, send_email_otp, verify_email_otp
)
from api.economics import calculate_business_metrics
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView, TokenObtainPairView
from api.serializers import EmailTokenObtainPairSerializer

class EmailTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer

router = DefaultRouter()
router.register(r'products', ProductViewSet)
router.register(r'sales', SaleViewSet)
router.register(r'debts', CustomerDebtViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('ocr/scan/', ocr_invoice_scanner_view, name='ocr-scan'),
    path('auth/send-otp/', send_email_otp, name='send-otp'),
    path('auth/verify-otp/', verify_email_otp, name='verify-otp'),
    path('analytics/economics/', calculate_business_metrics, name='business-economics'),
    path('auth/login/', EmailTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout/', TokenBlacklistView.as_view(), name='token_blacklist'),
]