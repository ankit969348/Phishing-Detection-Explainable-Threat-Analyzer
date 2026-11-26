from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"

    def ready(self):
        import sys
        if "runserver" not in sys.argv and "makemigrations" not in sys.argv and "migrate" not in sys.argv:
            try:
                from django.core.management import call_command
                call_command("migrate", interactive=False, verbosity=0)
            except Exception:
                pass
