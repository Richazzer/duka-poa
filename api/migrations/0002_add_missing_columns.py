from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS is_paid boolean DEFAULT false;
            """,
            reverse_sql="""
            ALTER TABLE api_customerdebt DROP COLUMN IF EXISTS is_paid;
            """
        ),
    ]
