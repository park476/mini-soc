import logging
import sys

from django.core.management.base import BaseCommand

from events.collector import DEFAULT_HOST, DEFAULT_PORT, make_server


class Command(BaseCommand):
    help = ('Receive "<nginx|ssh>\\t<log line>\\n" over TCP and store SecurityEvent / NormalizationFailure. '
            'The framing is a controlled format; the real victim rsyslog output is not verified yet.')

    def add_arguments(self, parser):
        parser.add_argument('--host', default=DEFAULT_HOST)
        parser.add_argument('--port', type=int, default=DEFAULT_PORT)

    def handle(self, *args, **options):
        logger = logging.getLogger('events.collector')
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        with make_server(options['host'], options['port']) as server:
            host, port = server.server_address[:2]
            self.stdout.write(self.style.SUCCESS(f'Collector listening on {host}:{port} (Ctrl+C to stop)'))
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stdout.write('Collector stopped')
