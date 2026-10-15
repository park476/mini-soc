import subprocess
from datetime import datetime, timedelta, timezone
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .models import Alert, ResponseRecord, ResponseVerification, SecurityEvent
from .response import check_ufw_rule, record_verification, respond_to_alert, run_responses

BASE = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone(timedelta(hours=9)))
ATTACKER = '192.0.2.50'
SAFE_SETTINGS = dict(
    RESPONSE_EXECUTE=False, RESPONSE_ALLOWLIST='', RESPONSE_VICTIM_HOST='',
    RESPONSE_VICTIM_USER='', RESPONSE_VICTIM_SSH_PORT='22', RESPONSE_SSH_KEY_PATH='',
    # The live override file must never be re-read into settings during tests (PB-01 refresh()).
    RESPONSE_OVERRIDES_FILE='/nonexistent/mini-soc-test.env', RESPONSE_OVERRIDES_ERROR='',
)


class FakeExecutor:
    label = 'fake-victim'

    def __init__(self, returncode=0, stdout='Rule inserted\n', stderr='', raises=None):
        self.calls = []
        self.result = SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
        self.raises = raises

    def run(self, remote_argv):
        self.calls.append(remote_argv)
        if self.raises:
            raise self.raises
        return self.result


def alert(rule_type='ssh_brute_force', ip=ATTACKER):
    event = SecurityEvent.objects.create(
        source_type='ssh' if rule_type == 'ssh_brute_force' else 'nginx', event_time=BASE,
        source_ip=ip, action='controlled', result='controlled', raw_log='controlled',
    )
    return Alert.objects.create(
        rule_type=rule_type, source_ip=ip, occurred_at=BASE, rule_condition='controlled',
        evidence='controlled', trigger_event=event,
    )


def no_real_subprocess(*args, **kwargs):
    raise AssertionError('subprocess.run must not be called in tests')


@override_settings(**SAFE_SETTINGS)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class ResponseExecutionTests(TestCase):
    def test_only_ssh_brute_force_is_a_trigger(self):
        ssh = alert()
        alert('nginx_scan')
        alert('nginx_suspicious_path')
        fake = FakeExecutor()
        records = run_responses(executor=fake)
        self.assertEqual([r.triggering_alert for r in records], [ssh])
        self.assertEqual(ResponseRecord.objects.count(), 1)
        for rule in ('nginx_scan', 'nginx_suspicious_path'):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                respond_to_alert(Alert.objects.get(rule_type=rule), executor=fake)

    def test_allowlisted_ip_is_skipped_without_executor(self):
        fake = FakeExecutor()
        with self.settings(RESPONSE_ALLOWLIST='10.0.0.1, 192.0.2.0/24'):
            record, _ = respond_to_alert(alert(), executor=fake)
        self.assertEqual(fake.calls, [])
        self.assertEqual((record.allowlist_result, record.execution_status), ('excluded', 'skipped'))
        self.assertIn('192.0.2.0/24', record.allowlist_detail)
        self.assertIsNone(record.executed_at)

    def test_invalid_allowlist_is_reported_not_ignored(self):
        fake = FakeExecutor()
        with self.settings(RESPONSE_ALLOWLIST='10.0.0.1,not-an-ip'):
            record, _ = respond_to_alert(alert(), executor=fake)
        self.assertEqual(fake.calls, [])
        self.assertEqual((record.allowlist_result, record.execution_status), ('unknown', 'failed'))
        self.assertIn("'not-an-ip'", record.failure_reason)

    def test_normal_ip_success_runs_fixed_ufw_command(self):
        fake = FakeExecutor()
        record, executed = respond_to_alert(alert(), executor=fake)
        self.assertTrue(executed)
        self.assertEqual(fake.calls, [['sudo', '-n', 'ufw', 'prepend', 'deny', 'proto', 'tcp',
                                       'from', ATTACKER, 'to', 'any', 'port', '22']])
        self.assertEqual((record.allowlist_result, record.execution_status), ('not_excluded', 'succeeded'))
        self.assertEqual((record.target_ip, record.action, record.victim), (ATTACKER, 'block_ssh', 'fake-victim'))
        self.assertIn('Rule inserted', record.execution_result)
        self.assertTrue(record.executed_at and record.completed_at)
        self.assertFalse(ResponseVerification.objects.exists())   # command success is not verification

    def test_remote_failure_and_sudo_password_are_recorded(self):
        record, _ = respond_to_alert(alert(), executor=FakeExecutor(returncode=255, stdout='', stderr='Permission denied'))
        self.assertEqual(record.execution_status, 'failed')
        self.assertIn('exit code 255', record.failure_reason)
        self.assertIn('Permission denied', record.execution_result)
        sudo = FakeExecutor(returncode=1, stdout='', stderr='sudo: a password is required')
        record, _ = respond_to_alert(alert(ip='192.0.2.51'), executor=sudo)
        self.assertEqual(record.execution_status, 'failed')
        self.assertIn('Non-interactive sudo', record.failure_reason)

    def test_timeout_is_unknown_and_missing_ssh_is_failed(self):
        timeout = FakeExecutor(raises=subprocess.TimeoutExpired('ssh', 30))
        record, _ = respond_to_alert(alert(), executor=timeout)
        self.assertEqual(record.execution_status, 'unknown')
        missing = FakeExecutor(raises=FileNotFoundError('ssh'))
        record, _ = respond_to_alert(alert(ip='192.0.2.51'), executor=missing)
        self.assertEqual(record.execution_status, 'failed')
        self.assertIn('could not be started', record.failure_reason)

    def test_invalid_source_ip_fails_safely(self):
        target = alert()
        for bad in ('999.1.1.1', None, '192.0.2.1; reboot'):
            with self.subTest(ip=bad):
                ResponseRecord.objects.filter(triggering_alert=target).delete()
                target.source_ip = bad                  # in-memory only: the DB column rejects these
                fake = FakeExecutor()
                record, _ = respond_to_alert(target, executor=fake)
                self.assertEqual(fake.calls, [])
                self.assertEqual(record.execution_status, 'failed')
                self.assertIsNone(record.target_ip)
                self.assertIn('Invalid source_ip', record.failure_reason)

    def test_missing_victim_config_never_executes(self):
        # No executor injected: settings decide, and subprocess.run is patched to fail if reached.
        target = alert()
        for overrides, expected in (
            ({}, 'RESPONSE_EXECUTE is not true'),
            ({'RESPONSE_EXECUTE': True}, 'Missing victim settings: RESPONSE_VICTIM_HOST, RESPONSE_VICTIM_USER'),
            ({'RESPONSE_EXECUTE': True, 'RESPONSE_VICTIM_HOST': '-oProxyCommand=x', 'RESPONSE_VICTIM_USER': 'soc'},
             'Invalid RESPONSE_VICTIM_HOST'),
        ):
            with self.subTest(overrides=overrides), self.settings(**overrides):
                ResponseRecord.objects.all().delete()
                call_command('run_response', stdout=StringIO())
                record = ResponseRecord.objects.get(triggering_alert=target)
                self.assertEqual(record.execution_status, 'failed')
                self.assertIn(expected, record.failure_reason)
                self.assertIsNone(record.executed_at)

    def test_rerun_does_not_duplicate_and_retry_updates_same_record(self):
        target = alert()
        failing = FakeExecutor(returncode=1, stdout='', stderr='boom')
        run_responses(executor=failing)
        self.assertEqual(run_responses(executor=failing), [])
        self.assertEqual(len(failing.calls), 1)
        ok = FakeExecutor()
        retried = run_responses(executor=ok, retry_failed=True)
        self.assertEqual(len(retried), 1)
        self.assertEqual(ResponseRecord.objects.get().execution_status, 'succeeded')
        self.assertEqual(run_responses(executor=ok, retry_failed=True), [])   # succeeded is never re-run
        self.assertEqual(len(ok.calls), 1)
        self.assertEqual(ResponseRecord.objects.get().triggering_alert, target)

    def test_alert_filter(self):
        first, second = alert(), alert(ip='192.0.2.51')
        run_responses(alert_id=second.pk, executor=FakeExecutor())
        self.assertEqual(list(ResponseRecord.objects.values_list('triggering_alert', flat=True)), [second.pk])
        self.assertFalse(ResponseRecord.objects.filter(triggering_alert=first).exists())


@override_settings(**SAFE_SETTINGS)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class ResponseVerificationTests(TestCase):
    def setUp(self):
        self.record, _ = respond_to_alert(alert(), executor=FakeExecutor())

    def test_success_requires_both_conditions(self):
        cases = [
            ('present', 'failed', 'success', True),
            ('present', 'succeeded', 'failed', False),
            ('absent', 'failed', 'failed', False),
            ('absent', 'succeeded', 'failed', False),
            ('present', 'unchecked', 'unverified', False),
            ('unchecked', 'failed', 'unverified', False),
            ('unchecked', 'unchecked', 'unverified', False),
        ]
        for ufw, reconnect, status, success in cases:
            with self.subTest(ufw=ufw, reconnect=reconnect):
                v = record_verification(self.record, ufw, 'unit test', reconnect, 'unit test')
                self.assertEqual((v.verification_status, v.success), (status, success))
                self.assertEqual(v.ufw_rule_present, ufw == 'present')
                self.assertEqual(v.reconnect_failed, reconnect == 'failed')

    def test_only_succeeded_records_can_be_verified(self):
        failed, _ = respond_to_alert(alert(ip='192.0.2.51'), executor=FakeExecutor(returncode=1))
        with self.assertRaises(ValueError):
            record_verification(failed, 'present', 'x', 'failed', 'x')

    def test_ufw_status_parsing(self):
        status = ('Status: active\n\nTo                         Action      From\n'
                  '--                         ------      ----\n'
                  '22/tcp                     DENY        192.0.2.50\n'
                  '22/tcp                     ALLOW       Anywhere\n')
        self.assertEqual(check_ufw_rule(FakeExecutor(stdout=status), ATTACKER)[0], 'present')
        self.assertEqual(check_ufw_rule(FakeExecutor(stdout=status), '192.0.2.5')[0], 'absent')
        self.assertEqual(check_ufw_rule(FakeExecutor(returncode=1, stdout=''), ATTACKER)[0], 'unchecked')

    def test_verify_command_defaults_to_unverified(self):
        call_command('verify_response', str(self.record.pk), stdout=StringIO())
        v = ResponseVerification.objects.get()
        self.assertEqual((v.ufw_rule_result, v.kali_ssh_reconnect_result, v.verification_status),
                         ('unchecked', 'unchecked', 'unverified'))
        call_command('verify_response', str(self.record.pk), '--check-ufw', stdout=StringIO())
        self.assertIn('RESPONSE_EXECUTE is not true', ResponseVerification.objects.last().ufw_check_evidence)
        with self.assertRaisesMessage(CommandError, 'requires --kali-evidence'):
            call_command('verify_response', str(self.record.pk), '--kali-reconnect', 'failed')


@override_settings(**SAFE_SETTINGS)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class ResponseApiTests(TestCase):
    def test_read_only_list_and_detail(self):
        client = APIClient()
        self.assertEqual(client.get('/api/responses/').json(), [])
        self.assertEqual(client.get('/api/responses/1/').status_code, 404)
        trigger = alert()
        record, _ = respond_to_alert(trigger, executor=FakeExecutor())
        detail = client.get(f'/api/responses/{record.pk}/').json()
        self.assertEqual(client.get('/api/responses/').json(), [detail])
        self.assertEqual(detail['target_ip'], ATTACKER)
        self.assertEqual(detail['triggering_alert_id'], trigger.pk)
        self.assertEqual(detail['triggering_alert']['rule_type'], 'ssh_brute_force')
        self.assertEqual((detail['action'], detail['execution_status'], detail['allowlist_result']),
                         ('block_ssh', 'succeeded', 'not_excluded'))
        self.assertIsNone(detail['verification'])
        record_verification(record, 'present', 'unit test', 'unchecked', 'unit test')
        v = client.get(f'/api/responses/{record.pk}/').json()['verification']
        self.assertEqual((v['ufw_rule_present'], v['reconnect_failed'], v['success'], v['verification_status']),
                         (True, False, False, 'unverified'))
        self.assertEqual(client.post('/api/responses/', {}, format='json').status_code, 405)
        self.assertEqual(client.delete(f'/api/responses/{record.pk}/').status_code, 405)
