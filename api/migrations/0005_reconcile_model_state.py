import django.conf
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_merge_20261112"),
        migrations.swappable_dependency(django.conf.settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.AddField(
                    model_name="businessprofile",
                    name="created_at",
                    field=models.DateTimeField(auto_now_add=True),
                ),
            ],
            state_operations=[
                migrations.AddField(
                    model_name="businessprofile",
                    name="created_at",
                    field=models.DateTimeField(auto_now_add=True),
                ),
                migrations.AddField(
                    model_name="product",
                    name="user",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="products",
                        to=django.conf.settings.AUTH_USER_MODEL,
                    ),
                ),
                migrations.AddField(
                    model_name="sale",
                    name="user",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sales",
                        to=django.conf.settings.AUTH_USER_MODEL,
                    ),
                ),
                migrations.AddField(
                    model_name="customerdebt",
                    name="user",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="debts",
                        to=django.conf.settings.AUTH_USER_MODEL,
                    ),
                ),
                migrations.AddField(
                    model_name="customerdebt",
                    name="is_paid",
                    field=models.BooleanField(default=False),
                ),
                migrations.AlterField(
                    model_name="customerdebt",
                    name="amount_owed",
                    field=models.DecimalField(decimal_places=2, default=0, max_digits=12),
                ),
                migrations.AlterField(
                    model_name="emailotp",
                    name="user",
                    field=models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="otps",
                        to=django.conf.settings.AUTH_USER_MODEL,
                    ),
                ),
                migrations.AlterField(
                    model_name="product",
                    name="category",
                    field=models.CharField(default="Duka", max_length=100),
                ),
                migrations.AlterField(
                    model_name="product",
                    name="price",
                    field=models.DecimalField(decimal_places=2, default=0, max_digits=12),
                ),
                migrations.AlterField(
                    model_name="sale",
                    name="total_amount",
                    field=models.DecimalField(decimal_places=2, default=0, max_digits=12),
                ),
            ],
        ),
    ]
