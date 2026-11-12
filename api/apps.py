from django.apps import AppConfig

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        """Automatically adds missing database columns to PostgreSQL on boot."""
        from django.db import connection
        try:
            with connection.cursor() as cursor:
                cursor.execute("ALTER TABLE api_product ADD COLUMN IF NOT EXISTS user_id integer;")
                cursor.execute("ALTER TABLE api_sale ADD COLUMN IF NOT EXISTS user_id integer;")
                cursor.execute("ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS user_id integer;")
                cursor.execute("ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS is_paid boolean DEFAULT false;")
        except Exception:
            pass
