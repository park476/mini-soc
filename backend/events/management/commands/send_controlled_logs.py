import socket

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = ('Send an already framed controlled file ("<nginx|ssh>\\t<log line>" per line) to the collector '
            'over TCP using the standard library. For local verification only; not a victim forwarder.')

    def add_arguments(self, parser):
        parser.add_argument('path')
        parser.add_argument('--host', default='127.0.0.1')
        parser.add_argument('--port', type=int, default=5514)

    def handle(self, *args, **options):
        try:
            with open(options['path'], 'rb') as sample:
                data = sample.read()
            with socket.create_connection((options['host'], options['port']), timeout=10) as conn:
                conn.sendall(data if data.endswith(b'\n') else data + b'\n')
        except OSError as exc:
            raise CommandError(f'Not sent: {exc}') from exc
        lines = sum(1 for line in data.splitlines() if line.strip())
        self.stdout.write(self.style.SUCCESS(f'Sent {lines} line(s) to {options["host"]}:{options["port"]}'))
