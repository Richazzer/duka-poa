from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0002_add_user_columns"),
        ("api", "0002_businessprofile"),
        ("api", "0003_cleanup_customerdebt_schema"),
    ]

    operations = []
