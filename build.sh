#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate --no-input

# 💥 DIRECTLY ADDS THE MISSING COLUMNS TO POSTGRESQL ON RENDER 💥
python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'duka_backend.settings')
django.setup()
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute('ALTER TABLE api_product ADD COLUMN IF NOT EXISTS user_id integer REFERENCES auth_user(id);')
    cursor.execute('ALTER TABLE api_sale ADD COLUMN IF NOT EXISTS user_id integer REFERENCES auth_user(id);')
    cursor.execute('ALTER TABLE api_customerdebt ADD COLUMN IF NOT EXISTS user_id integer REFERENCES auth_user(id);')
print('✅ [USER_ID COLUMNS SUCCESSFULLY CREATED IN POSTGRESQL]')
"

# Create superuser if needed
python manage.py createsuperuser --no-input || true
