from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from events.models import ManualBlockRecord, UnblockRecord

MODELS = {'block': ManualBlockRecord, 'unblock': UnblockRecord}
# Effect verified: the rule state after the change and a new connection from the attacker host agree.
EXPECTED = {'block': ('present', 'failed'), 'unblock': ('absent', 'succeeded')}


class Command(BaseCommand):
    help = ('Record a new SSH connection attempt really made from the attacker host after a manual SSH block '
            '(expect failed) or unblock (expect succeeded). Separate from the command result.')

    def add_arguments(self, parser):
        parser.add_argument('operation', choices=sorted(MODELS), help='block = ManualBlockRecord, unblock = UnblockRecord')
        parser.add_argument('record_id', type=int)
        parser.add_argument('reconnect', choices=['failed', 'succeeded'], help='Result of the new SSH connection attempt')
        parser.add_argument('--evidence', required=True, help='How it was observed, e.g. the nc/ssh command and output')

    def handle(self, *args, operation, record_id, reconnect, evidence, **options):
        try:
            record = MODELS[operation].objects.get(pk=record_id)
        except MODELS[operation].DoesNotExist as exc:
            raise CommandError(f'{MODELS[operation].__name__} #{record_id} does not exist.') from exc
        if not record.target_ip or record.execution_status not in ('succeeded', 'skipped'):
            raise CommandError(f'{type(record).__name__} #{record.pk} is {record.execution_status}; '
                               'only a completed change can be verified.')
        record.kali_ssh_reconnect_result, record.reconnect_check_evidence = reconnect, evidence
        record.reconnect_checked_at = timezone.now()
        record.save(update_fields=['kali_ssh_reconnect_result', 'reconnect_check_evidence', 'reconnect_checked_at'])
        verified = (record.ufw_after_result, reconnect) == EXPECTED[operation]
        self.stdout.write(f'{type(record).__name__} #{record.pk} {operation} {record.target_ip}: UFW {record.ufw_after_result}, '
                          f'new SSH connection {reconnect} -> {"verified" if verified else "not verified"}')
