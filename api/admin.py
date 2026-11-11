from django.contrib import admin
from .models import Product, Sale, CustomerDebt, EmailOTP, BusinessProfile

# Custom Admin Header
admin.site.site_header = "Duka Poa POS - Mfumo Mkuu wa Utawala"
admin.site.site_title = "Duka Poa Admin"
admin.site.index_title = "Usimamizi wa Maduka, Bidhaa na Mauzo"


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'price', 'stock', 'user', 'created_at')
    list_filter = ('category', 'created_at', 'user')
    search_fields = ('name', 'category', 'user__username', 'user__email')
    list_editable = ('price', 'stock')  # Fast price & stock edits directly in the table
    ordering = ('-created_at',)
    list_per_page = 25


@admin.register(Sale)
class SaleAdmin(admin.ModelAdmin):
    list_display = ('id', 'customer_name', 'total_amount', 'payment_method', 'user', 'created_at')
    list_filter = ('payment_method', 'created_at', 'user')
    search_fields = ('customer_name', 'user__username', 'user__email', 'id')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)
    list_per_page = 25


@admin.register(CustomerDebt)
class CustomerDebtAdmin(admin.ModelAdmin):
    list_display = ('customer_name', 'amount_owed', 'phone', 'is_paid', 'user', 'created_at')
    list_filter = ('is_paid', 'created_at', 'user')
    search_fields = ('customer_name', 'phone', 'user__username', 'user__email')
    list_editable = ('is_paid',)  # Fast toggle to mark debts as paid
    ordering = ('-created_at',)
    list_per_page = 25

    actions = ['mark_paid', 'mark_unpaid']

    @admin.action(description="Weka alama kuwa wamelipa (Mark as Paid)")
    def mark_paid(self, request, queryset):
        queryset.update(is_paid=True)

    @admin.action(description="Weka alama kuwa hawajalipa (Mark as Unpaid)")
    def mark_unpaid(self, request, queryset):
        queryset.update(is_paid=False)


@admin.register(BusinessProfile)
class BusinessProfileAdmin(admin.ModelAdmin):
    list_display = ('business_name', 'user', 'business_type', 'is_onboarded')
    list_filter = ('business_type', 'is_onboarded')
    search_fields = ('business_name', 'user__username', 'user__email')
    list_editable = ('is_onboarded',)
    list_per_page = 25


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'is_verified', 'created_at')
    list_filter = ('is_verified', 'created_at')
    search_fields = ('user__email', 'user__username', 'otp')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)
    list_per_page = 30