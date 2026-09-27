from django.core.management.base import BaseCommand

from events.response import run_responses


class Command(BaseCommand):
    help = ('Run the SSH block response for ssh_brute_force Alerts that have no ResponseRecord yet (T5). '
            'Remote commands are sent only when RESPONSE_EXECUTE=true and the victim settings are complete.')

    def add_arguments(self, parser):
        parser.add_argument('--alert', type=int, help='Process only this Alert id.')
        parser.add_argument('--retry-failed', action='store_true',
                            help='Re-run records whose execution_status is failed (same record is updated).')

    def handle(self, *args, **options):
        records = run_responses(alert_id=options['alert'], retry_failed=options['retry_failed'])
        for r in records:
            reason = f' - {r.failure_reason}' if r.failure_reason else ''
            self.stdout.write(f'ResponseRecord #{r.pk} alert #{r.triggering_alert_id} '
                              f'{r.target_ip or "-"}: {r.execution_status}{reason}')
        self.stdout.write(self.style.SUCCESS(f'Processed {len(records)} ResponseRecord(s)'))
