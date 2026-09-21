from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from events.models import SecurityEvent
from events.nginx import normalize_nginx


class Command(BaseCommand):
    help = 'Store exactly one controlled Nginx combined-format sample from a UTF-8 file.'

    def add_arguments(self, parser):
        parser.add_argument('path')

    def handle(self, *args, **options):
        try:
            with open(options['path'], encoding='utf-8', newline='') as sample:
                raw_log = sample.read()
            event = SecurityEvent(**normalize_nginx(raw_log))
            event.full_clean()
        except (OSError, UnicodeError, ValueError, ValidationError) as exc:
            raise CommandError(f'Sample was not saved: {exc}') from exc
        event.save()
        self.stdout.write(self.style.SUCCESS(f'Saved SecurityEvent id={event.pk}'))
