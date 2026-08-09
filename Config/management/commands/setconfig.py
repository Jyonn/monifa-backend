from django.core.management.base import BaseCommand

from Config.models import Config, ConfigInstance


class Command(BaseCommand):
    help = "Create or update a Monifa database configuration value"

    def add_arguments(self, parser):
        parser.add_argument("key", choices=[
            value for name, value in vars(ConfigInstance).items()
            if name.isupper() and isinstance(value, str)
        ])
        parser.add_argument("value")

    def handle(self, *args, **options):
        Config.update_value(options["key"], options["value"])
        self.stdout.write(self.style.SUCCESS(f"Updated {options['key']}"))

