from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from events.models import NormalizationFailure, SecurityEvent
from events.ssh import normalize_ssh


class Command(BaseCommand):
    help = 'Store a controlled sshd authentication sample; unparsable lines become NormalizationFailure.'

    def add_arguments(self, parser):
        parser.add_argument('path')

    def handle(self, *args, **options):
        try:
            with open(options['path'], encoding='utf-8', newline='') as sample:
                lines = [line for line in sample.read().splitlines(keepends=True) if line.strip()]
        except (OSError, UnicodeError) as exc:
            raise CommandError(f'Sample was not read: {exc}') from exc
        if not lines:
            raise CommandError('Sample was not read: file has no log lines.')
        saved = failed = 0
        with transaction.atomic():
            for raw_log in lines:
                try:
                    event = SecurityEvent(**normalize_ssh(raw_log))
                    event.full_clean()
                except (ValueError, ValidationError) as exc:
                    NormalizationFailure.objects.create(
                        source_type='ssh', raw_log=raw_log, failure_reason=str(exc),
                    )
                    failed += 1
                    continue
                event.save()
                saved += 1
        self.stdout.write(self.style.SUCCESS(
            f'Saved {saved} SecurityEvent(s), {failed} NormalizationFailure(s)'
        ))
