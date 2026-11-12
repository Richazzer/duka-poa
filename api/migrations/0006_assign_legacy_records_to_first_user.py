from django.conf import settings
from django.db import migrations


def assign_unowned_records(apps, schema_editor):
    database = schema_editor.connection.alias
    app_label, model_name = settings.AUTH_USER_MODEL.split(".")
    User = apps.get_model(app_label, model_name)
    owner = User.objects.using(database).order_by("pk").first()
    if owner is None:
        return

    for model_name in ("Product", "Sale", "CustomerDebt"):
        model = apps.get_model("api", model_name)
        model.objects.using(database).filter(user_id__isnull=True).update(user_id=owner.pk)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0005_reconcile_model_state"),
    ]

    operations = [
        migrations.RunPython(assign_unowned_records, migrations.RunPython.noop),
    ]
