from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('api', '__first__'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            ALTER TABLE api_product ADD COLUMN IF NOT EXISTS user_id integer REFERENCES auth_user(id);
            ALTER TABLE api_sale ADD COLUMN IF NOT EXISTS user_id integer REFERENCES auth_user(id);
            ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS user_id integer REFERENCES auth_user(id);
            """,
            reverse_sql="""
            ALTER TABLE api_product DROP COLUMN IF EXISTS user_id;
            ALTER TABLE api_sale DROP COLUMN IF EXISTS user_id;
            ALTER TABLE api_customerdebt DROP COLUMN IF EXISTS user_id;
            """
        ),
    ]