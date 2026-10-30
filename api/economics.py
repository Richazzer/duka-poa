from datetime import timedelta
from django.utils import timezone
from django.db.models import Sum, Count
from .models import Sale, CustomerDebt

def calculate_business_metrics():
    now = timezone.now()
    thirty_days_ago = now - timedelta(days=30)
    sixty_days_ago = now - timedelta(days=60)

    # 1. Monthly Recurring Revenue (MRR) - Estimated from subscription/repeat sales in last 30 days
    current_month_sales = Sale.objects.filter(created_at__gte=thirty_days_ago).aggregate(total=Sum('total_amount'))['total'] or 0
    mrr = float(current_month_sales)

    # 2. Annual Recurring Revenue (ARR)
    arr = mrr * 12

    # 3. Previous Month Sales for Churn / Growth Rate
    prev_month_sales = Sale.objects.filter(created_at__gte=sixty_days_ago, created_at__lt=thirty_days_ago).aggregate(total=Sum('total_amount'))['total'] or 0
    prev_mrr = float(prev_month_sales)

    # 4. Growth Rate & Churn Rate
    if prev_mrr > 0:
        growth_rate = ((mrr - prev_mrr) / prev_mrr) * 100
        churn_rate = max(0, -growth_rate) # Churn rate as percentage loss
    else:
        growth_rate = 100.0 if mrr > 0 else 0.0
        churn_rate = 0.0

    # 5. Total Uncollected Debt (Accounts Receivable / Liability)
    total_unpaid_debts = CustomerDebt.objects.filter(status='Pending').aggregate(total=Sum('amount_owed'))['total'] or 0

    # 6. Burn Rate & Runway (Estimated operating expense buffer)
    # Assuming baseline fixed operating expense baseline
    estimated_monthly_expenses = float(mrr * 0.45)  # 45% estimated cost of goods & overhead
    net_burn_rate = max(0, estimated_monthly_expenses - mrr)

    return {
        "mrr": mrr,
        "arr": arr,
        "growth_rate": round(growth_rate, 2),
        "churn_rate": round(churn_rate, 2),
        "unpaid_debts": float(total_unpaid_debts),
        "estimated_expenses": round(estimated_monthly_expenses, 2),
        "net_burn_rate": round(net_burn_rate, 2),
        "currency": "TZS"
    }