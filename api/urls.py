from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api.views import (
    ProductViewSet, SaleViewSet, CustomerDebtViewSet, 
    ocr_invoice_scanner_view, send_email_otp, verify_email_otp
)
from api.economics import calculate_business_metrics

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
]