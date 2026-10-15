from django.core.management.base import BaseCommand, CommandError

from events.models import WebBlockRecord
from events.web_block import record_http_check


class Command(BaseCommand):
    help = ('Record the HTTP status actually observed from the attacker host after a web block (expect 403) '
            'or unblock (expect 200). Separate from the helper command result.')

    def add_arguments(self, parser):
        parser.add_argument('record_id', type=int, help='WebBlockRecord id')
        parser.add_argument('http_status', type=int, help='HTTP status observed on the attacker host')
        parser.add_argument('--evidence', required=True, help='How it was observed, e.g. the curl command and output')

    def handle(self, *args, record_id, http_status, evidence, **options):
        try:
            record = record_http_check(WebBlockRecord.objects.get(pk=record_id), http_status, evidence)
        except WebBlockRecord.DoesNotExist as exc:
            raise CommandError(f'WebBlockRecord #{record_id} does not exist.') from exc
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(f'WebBlockRecord #{record.pk} {record.operation} {record.target_ip}: '
                          f'HTTP {record.http_check_status} -> {record.http_check_result}')
