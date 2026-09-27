from django.core.management.base import BaseCommand, CommandError

from events.models import ResponseRecord
from events.response import ResponseConfigError, SshExecutor, check_ufw_rule, record_verification


class Command(BaseCommand):
    help = ('Record a ResponseVerification. UFW state is read from the victim (--check-ufw) or entered from an '
            'observed `ufw status`; the Kali SSH reconnect result is entered from a real observation. '
            'success requires ufw rule present AND reconnect failed.')

    def add_arguments(self, parser):
        parser.add_argument('response_id', type=int)
        ufw = parser.add_mutually_exclusive_group()
        ufw.add_argument('--check-ufw', action='store_true', help='Read `sudo -n ufw status` on the victim over SSH.')
        ufw.add_argument('--ufw', choices=['present', 'absent'], help='Observed UFW rule state (needs --ufw-evidence).')
        parser.add_argument('--ufw-evidence', default='')
        parser.add_argument('--kali-reconnect', choices=['failed', 'succeeded'],
                            help='Observed SSH reconnect result from the same Kali (needs --kali-evidence).')
        parser.add_argument('--kali-evidence', default='')

    def handle(self, *args, **options):
        try:
            record = ResponseRecord.objects.get(pk=options['response_id'])
        except ResponseRecord.DoesNotExist as exc:
            raise CommandError('ResponseRecord not found.') from exc
        if options['ufw'] and not options['ufw_evidence'].strip():
            raise CommandError('--ufw requires --ufw-evidence.')
        if options['kali_reconnect'] and not options['kali_evidence'].strip():
            raise CommandError('--kali-reconnect requires --kali-evidence.')

        ufw_result, ufw_evidence = 'unchecked', 'UFW rule was not checked.'
        if options['check_ufw']:
            try:
                ufw_result, ufw_evidence = check_ufw_rule(SshExecutor.from_settings(), record.target_ip)
            except ResponseConfigError as exc:
                ufw_evidence = f'UFW rule was not checked: {exc}'
        elif options['ufw']:
            ufw_result, ufw_evidence = options['ufw'], f'Manual observation: {options["ufw_evidence"].strip()}'
        reconnect = options['kali_reconnect'] or 'unchecked'
        reconnect_evidence = (f'Manual observation: {options["kali_evidence"].strip()}' if options['kali_reconnect']
                              else 'Kali SSH reconnect was not checked.')
        try:
            v = record_verification(record, ufw_result, ufw_evidence, reconnect, reconnect_evidence)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(
            f'ResponseVerification #{v.pk}: ufw={v.ufw_rule_result}, reconnect={v.kali_ssh_reconnect_result}, '
            f'status={v.verification_status}'
        ))
