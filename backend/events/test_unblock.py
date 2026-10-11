import subprocess
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from .models import ResponseRecord, ResponseVerification, UnblockRecord
from .test_response import ATTACKER, SAFE_SETTINGS, alert, no_real_subprocess
from .unblock import unblock_response

STATUS = ['sudo', '-n', 'ufw', 'status']
DELETE = ['sudo', '-n', 'ufw', 'delete', 'deny', 'proto', 'tcp', 'from', ATTACKER, 'to', 'any', 'port', '22']
BLOCKED = f'Status: active\n\nTo                         Action      From\n22/tcp                     DENY        {ATTACKER}\n22/tcp                     ALLOW       Anywhere\n'
OPEN = 'Status: active\n\nTo                         Action      From\n22/tcp                     ALLOW       Anywhere\n'
UNBLOCK_ON = dict(SAFE_SETTINGS, RESPONSE_UNBLOCK_EXECUTE=True)
CHANGELIST = '/admin/events/responserecord/'


def out(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class ScriptedExecutor:
    """Returns the scripted results in order; an exception instance is raised instead."""
    label = 'fake-victim'

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def run(self, remote_argv):
        self.calls.append(remote_argv)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def block_record(status='succeeded', ip=ATTACKER):
    return ResponseRecord.objects.create(
        triggering_alert=alert(), target_ip=ip, allowlist_result='not_excluded', execution_status=status,
        command='controlled', executed_at=timezone.now(),
    )


def snapshot(record):
    return ResponseRecord.objects.filter(pk=record.pk).values().get()


@override_settings(**UNBLOCK_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class UnblockServiceTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser('root-admin', password='pw')

    def test_normal_unblock_checks_deletes_rechecks(self):
        record = block_record()
        verification = ResponseVerification.objects.create(
            response=record, ufw_rule_result='present', kali_ssh_reconnect_result='failed')
        before = snapshot(record)
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN))
        audit = unblock_response(record, self.admin, executor=fake)
        self.assertEqual(fake.calls, [STATUS, DELETE, STATUS])
        self.assertEqual((audit.execution_status, audit.failure_kind), ('succeeded', ''))
        self.assertEqual((audit.ufw_before_result, audit.ufw_after_result), ('present', 'absent'))
        self.assertEqual((audit.requested_by, audit.requested_by_username, audit.target_ip),
                         (self.admin, 'root-admin', ATTACKER))
        self.assertEqual(audit.kali_ssh_reconnect_result, 'unchecked')
        self.assertIsNotNone(audit.completed_at)
        # Past evidence is untouched.
        self.assertEqual(snapshot(record), before)
        verification.refresh_from_db()
        self.assertEqual(verification.verification_status, 'success')

    def test_already_unblocked_sends_no_delete(self):
        fake = ScriptedExecutor(out(stdout=OPEN))
        audit = unblock_response(block_record(), self.admin, executor=fake)
        self.assertEqual(fake.calls, [STATUS])
        self.assertEqual((audit.execution_status, audit.ufw_before_result), ('skipped', 'absent'))
        self.assertIn('already unblocked', audit.failure_reason)

    def test_other_ip_or_port_rule_is_not_a_match(self):
        other = OPEN + '22/tcp                     DENY        192.0.2.5\n80/tcp                     DENY        ' + ATTACKER + '\n'
        fake = ScriptedExecutor(out(stdout=other))
        audit = unblock_response(block_record(), self.admin, executor=fake)
        self.assertEqual(fake.calls, [STATUS])
        self.assertEqual(audit.execution_status, 'skipped')

    def test_invalid_ip_sends_nothing(self):
        record = block_record()
        record.target_ip = '192.0.2.50; reboot'  # not saved: the stored value can never reach a command
        for bad in (record, block_record(ip=None)):
            fake = ScriptedExecutor()
            audit = unblock_response(bad, self.admin, executor=fake)
            self.assertEqual(fake.calls, [])
            self.assertEqual((audit.execution_status, audit.failure_kind), ('failed', 'invalid_ip'))

    def test_only_succeeded_blocks_are_eligible(self):
        for status in ('failed', 'skipped', 'unknown'):
            fake = ScriptedExecutor()
            audit = unblock_response(block_record(status), self.admin, executor=fake)
            self.assertEqual(fake.calls, [])
            self.assertEqual(audit.failure_kind, 'not_eligible')

    def test_disabled_setting_sends_nothing_even_if_block_execute_is_on(self):
        fake = ScriptedExecutor()
        with self.settings(RESPONSE_UNBLOCK_EXECUTE=False, RESPONSE_EXECUTE=True):
            audit = unblock_response(block_record(), self.admin, executor=fake)
        self.assertEqual(fake.calls, [])
        self.assertEqual(audit.failure_kind, 'config')
        self.assertIn('RESPONSE_UNBLOCK_EXECUTE', audit.failure_reason)

    def test_unblock_flag_does_not_need_or_enable_block_execute(self):
        # RESPONSE_EXECUTE stays False; missing victim settings are reported, nothing is sent.
        audit = unblock_response(block_record(), self.admin)
        self.assertEqual(audit.failure_kind, 'config')
        self.assertIn('RESPONSE_VICTIM_HOST', audit.failure_reason)
        from .response import ResponseConfigError, SshExecutor
        with self.assertRaisesMessage(ResponseConfigError, 'RESPONSE_EXECUTE is not true'):
            SshExecutor.from_settings()

    def test_ssh_error_sudo_denied_and_timeout_are_distinguished(self):
        cases = [
            ('ssh_error', [out(255, stderr='ssh: connect to host 192.0.2.9 port 22: Connection refused')], 'failed'),
            ('ssh_error', [OSError('ssh not found')], 'failed'),
            ('timeout', [subprocess.TimeoutExpired('ssh', 30)], 'failed'),
            ('sudo_denied', [out(1, stderr='sudo: a password is required')], 'failed'),
            ('sudo_denied', [out(stdout=BLOCKED), out(1, stderr='sudo: a password is required')], 'failed'),
            ('ssh_error', [out(stdout=BLOCKED), out(255, stderr='Connection closed')], 'failed'),
            ('timeout', [out(stdout=BLOCKED), subprocess.TimeoutExpired('ssh', 30)], 'unknown'),
            ('command_failed', [out(stdout=BLOCKED), out(1, stderr='ERROR: problem running')], 'failed'),
        ]
        for kind, script, status in cases:
            with self.subTest(kind=kind, steps=len(script)):
                fake = ScriptedExecutor(*script)
                audit = unblock_response(block_record(), self.admin, executor=fake)
                self.assertEqual((audit.failure_kind, audit.execution_status), (kind, status))
                self.assertEqual(len(fake.calls), len(script))  # stops at the first failure

    def test_rule_still_present_and_recheck_failure_are_reported(self):
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=BLOCKED))
        audit = unblock_response(block_record(), self.admin, executor=fake)
        self.assertEqual((audit.execution_status, audit.ufw_after_result, audit.failure_kind),
                         ('succeeded', 'present', 'rule_still_present'))
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(255, stderr='closed'))
        audit = unblock_response(block_record(), self.admin, executor=fake)
        self.assertEqual((audit.execution_status, audit.ufw_after_result, audit.failure_kind),
                         ('succeeded', 'unchecked', 'ssh_error'))


@override_settings(**UNBLOCK_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class UnblockAdminTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.admin = users.create_superuser('root-admin', password='pw')
        self.staff = users.create_user('staff', password='pw', is_staff=True)
        self.user = users.create_user('plain', password='pw')
        self.record = block_record()
        self.client.force_login(self.admin)

    def post(self, client=None, **extra):
        data = {'action': 'unblock_ssh', '_selected_action': [self.record.pk], **extra}
        return (client or self.client).post(CHANGELIST, data)

    def confirm(self, fake, **extra):
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake) as from_settings:
            response = self.post(confirm_unblock='yes', acknowledge='on', **extra)
        return response, from_settings

    def test_superuser_sees_confirmation_without_executing(self):
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, ATTACKER)
        self.assertContains(response, f'sudo -n ufw delete deny proto tcp from {ATTACKER} to any port 22')
        self.assertContains(response, f'#{self.record.triggering_alert_id}')
        self.assertContains(response, '위험성')
        self.assertEqual(UnblockRecord.objects.count(), 0)

    def test_superuser_confirmed_post_unblocks(self):
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN))
        response, from_settings = self.confirm(fake)
        self.assertRedirects(response, CHANGELIST)
        from_settings.assert_called_once_with('RESPONSE_UNBLOCK_EXECUTE')
        self.assertEqual(fake.calls, [STATUS, DELETE, STATUS])
        audit = UnblockRecord.objects.get()
        self.assertEqual((audit.requested_by, audit.execution_status, audit.ufw_after_result),
                         (self.admin, 'succeeded', 'absent'))

    def test_duplicate_unblock_is_skipped(self):
        self.confirm(ScriptedExecutor(out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN)))
        fake = ScriptedExecutor(out(stdout=OPEN))
        self.confirm(fake)
        self.assertEqual(fake.calls, [STATUS])
        self.assertEqual(list(UnblockRecord.objects.order_by('id').values_list('execution_status', flat=True)),
                         ['succeeded', 'skipped'])

    def test_missing_acknowledgement_does_not_execute(self):
        fake = ScriptedExecutor()
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake):
            response = self.post(confirm_unblock='yes')
        self.assertEqual(response.status_code, 200)
        self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))

    def test_posted_ip_or_command_is_ignored(self):
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN))
        self.confirm(fake, target_ip='203.0.113.9', command='sudo reboot', ip='203.0.113.9')
        self.assertEqual(fake.calls, [STATUS, DELETE, STATUS])
        self.assertEqual(UnblockRecord.objects.get().target_ip, ATTACKER)

    def test_failed_block_record_is_not_executed(self):
        self.record = block_record('failed')
        fake = ScriptedExecutor()
        self.confirm(fake)
        self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))

    def test_get_never_executes(self):
        fake = ScriptedExecutor()
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake):
            response = self.client.get(CHANGELIST, {
                'action': 'unblock_ssh', '_selected_action': self.record.pk, 'confirm_unblock': 'yes', 'acknowledge': 'on'})
        self.assertIn(response.status_code, (200, 302))
        self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))

    def test_csrf_is_enforced(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        fake = ScriptedExecutor()
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake):
            response = self.post(client, confirm_unblock='yes', acknowledge='on')
        self.assertEqual(response.status_code, 403)
        self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))

    def test_non_superusers_are_denied(self):
        from django.contrib.auth.models import Permission
        self.staff.user_permissions.set(Permission.objects.filter(content_type__app_label='events'))
        for who in (self.staff, self.user, None):
            with self.subTest(user=getattr(who, 'username', 'anonymous')):
                client = Client()
                if who:
                    client.force_login(who)
                fake = ScriptedExecutor()
                with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake):
                    response = self.post(client, confirm_unblock='yes', acknowledge='on')
                    confirmation = self.post(client)
                self.assertNotContains(confirmation, 'ufw delete', status_code=confirmation.status_code)
                if who is not self.staff:
                    self.assertEqual(response.status_code, 302)
                    self.assertIn('/admin/login/', response['Location'])
                self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))

    def test_past_records_cannot_be_edited_or_deleted_in_admin(self):
        self.assertEqual(self.client.post(f'{CHANGELIST}{self.record.pk}/change/', {'target_ip': '203.0.113.9'}).status_code, 403)
        self.assertEqual(self.client.post(f'{CHANGELIST}{self.record.pk}/delete/', {'post': 'yes'}).status_code, 403)
        self.assertEqual(self.client.get('/admin/events/unblockrecord/add/').status_code, 403)
        self.assertEqual(snapshot(self.record)['target_ip'], ATTACKER)

    def test_reconnect_observation_is_the_only_editable_audit_field(self):
        audit = unblock_response(self.record, self.admin, executor=ScriptedExecutor(
            out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN)))
        url = f'/admin/events/unblockrecord/{audit.pk}/change/'
        response = self.client.post(url, {
            'kali_ssh_reconnect_result': 'succeeded', 'reconnect_check_evidence': 'ssh from Kali connected',
            'target_ip': '203.0.113.9', 'execution_status': 'failed'})
        self.assertEqual(response.status_code, 302)
        audit.refresh_from_db()
        self.assertEqual((audit.kali_ssh_reconnect_result, audit.target_ip, audit.execution_status),
                         ('succeeded', ATTACKER, 'succeeded'))
