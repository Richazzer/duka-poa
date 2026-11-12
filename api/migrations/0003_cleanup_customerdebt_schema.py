from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0002_add_missing_columns'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS user_id integer;
            ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS is_paid boolean DEFAULT false;
            ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS phone varchar(20);
            ALTER TABLE api_customerdebt DROP COLUMN IF EXISTS notes;
            """,
            reverse_sql="""
            ALTER TABLE api_customerdebt DROP COLUMN IF EXISTS notes;
            """,
        ),
    ]
