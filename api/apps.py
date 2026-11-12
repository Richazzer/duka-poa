from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'
    # Do not mutate the database in AppConfig.ready(); let migrations handle schema changes.
