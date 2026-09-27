import logging
import sys
import time

from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections
from django.utils import timezone

from events.analysis import format_summary, run_cycle

DEFAULT_INTERVAL = 10.0
MIN_INTERVAL = 1.0


class Command(BaseCommand):
    help = ('Repeatedly run detection -> response (only if RESPONSE_EXECUTE=true) -> correlation/risk/Incident '
            'over stored data. Separate from the collector process.')

    def add_arguments(self, parser):
        parser.add_argument('--once', action='store_true', help='Run exactly one cycle and exit (non-zero on error).')
        parser.add_argument('--interval', type=float, default=DEFAULT_INTERVAL,
                            help=f'Seconds between cycles (default {DEFAULT_INTERVAL:g}, minimum {MIN_INTERVAL:g}).')

    def handle(self, *args, **options):
        interval = options['interval']
        if not interval >= MIN_INTERVAL:
            raise CommandError(f'--interval must be at least {MIN_INTERVAL:g} second(s).')
        logger = logging.getLogger('events.analysis')
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)

        if options['once']:
            summary = run_cycle()
            self.stdout.write(format_summary(summary))
            if summary['errors']:
                raise CommandError('Analysis cycle had errors: ' + '; '.join(summary['errors']))
            return

        self.stdout.write(self.style.SUCCESS(f'Analysis loop started (every {interval:g}s, Ctrl+C to stop)'))
        try:
            while True:
                close_old_connections()   # recover from dropped DB connections between cycles
                summary = run_cycle()
                self.stdout.write(f'{timezone.localtime():%H:%M:%S} {format_summary(summary)}')
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stdout.write('Analysis loop stopped')
