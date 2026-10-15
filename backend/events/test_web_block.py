import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings

from config import response_overrides

from .models import Incident, ManualBlockRecord, ResponseRecord, UnblockRecord, WebBlockRecord
from .test_response import ATTACKER as FIXTURE_IP, no_real_subprocess
from .test_threats import PANEL_ON, REAL as SSH_TARGET
from .test_unblock import ScriptedExecutor, alert, out

API = '/api/admin-panel/'
# Any alerted public IP is a target; nothing is pre-registered. IP_C gets its first Alert during a test.
IP_A, IP_B, IP_C, PROTECTED, UNALERTED = '118.235.65.6', '1.1.1.1', '2606:4700:4700::1111', '119.194.231.131', '9.9.9.9'
LAB = '172.22.16.235'  # private attacker; blockable only inside RESPONSE_WEB_PRIVATE_RANGES
HELPER = '/usr/local/sbin/mini-soc-webblock'
STATUS = ['sudo', '-n', HELPER, 'status']
OPEN = '# mini-soc web blocklist (Nginx 8080)\n'


def cmd(operation, ip):
    return ['sudo', '-n', HELPER, operation, ip]


def listed(*ips):
    return OPEN + ''.join(f'deny {ip};\n' for ip in ips)


WEB_ON = dict(PANEL_ON, RESPONSE_WEB_BLOCK_EXECUTE=True, RESPONSE_WEB_PRIVATE_RANGES='',
              RESPONSE_ALLOWLIST=f'172.18.20.65,172.18.20.161,172.29.176.40,{PROTECTED}', RESPONSE_OVERRIDES_ERROR='')
FAILURE = {'not_detected': 403, 'fixture': 403, 'invalid_ip': 409, 'not_public': 403, 'allowlisted': 403,
           'self': 403, 'config': 503}


@override_settings(**WEB_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class WebBlockPanelTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.admin = users.create_superuser('root', password='pw')
        self.staff = users.create_user('staff', password='pw', is_staff=True)
        alert('nginx_scan', ip=IP_A)
        alert('nginx_suspicious_path', ip=IP_A)
        alert('nginx_scan', ip=IP_B)
        alert('nginx_scan', ip=PROTECTED)
        alert('nginx_scan', ip=LAB)
        alert(ip=SSH_TARGET)
        alert(ip=FIXTURE_IP)
        self.client.force_login(self.admin)

    def post(self, path, body=None, client=None, **extra):
        return (client or self.client).post(API + path, json.dumps(body or {}), content_type='application/json', **extra)

    def act(self, action, script, ip=IP_A, body=None, **extra):
        fake = ScriptedExecutor(*script)
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake) as from_settings:
            response = self.post(f'threats/{action}/', {'ip': ip, 'confirm': True} if body is None else body, **extra)
        return response, fake, from_settings

    def block(self, ip, before=OPEN, after=None):
        return self.act('web-block', [out(stdout=before), out(stdout=f'{ip} blocked\n'), out(stdout=after or listed(ip))], ip=ip)

    def unblock(self, ip, before=None, after=OPEN):
        return self.act('web-unblock', [out(stdout=before or listed(ip)), out(stdout=f'{ip} unblocked\n'), out(stdout=after)], ip=ip)

    def threats(self, **extra):
        return {t['ip']: t for t in self.client.get(API + 'threats/', **extra).json()['threats']}

    def test_anonymous_non_superuser_and_csrf_are_denied(self):
        for client, status in ((Client(), 401), (Client(), 403)):
            if status == 403:
                client.force_login(self.staff)
            fake = ScriptedExecutor()
            with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
                statuses = [self.post(p, {'ip': IP_A, 'confirm': True}, client).status_code
                            for p in ('web-status/', 'threats/web-block/', 'threats/web-unblock/')]
            self.assertEqual((statuses, fake.calls), ([status] * 3, []))
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        fake = ScriptedExecutor()
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
            statuses = [self.post(p, {'ip': IP_A, 'confirm': True}, client).status_code
                        for p in ('web-status/', 'threats/web-block/', 'threats/web-unblock/')]
        self.assertEqual((statuses, fake.calls, WebBlockRecord.objects.count()), ([403] * 3, [], 0))
        for path in ('web-status/', 'threats/web-block/', 'threats/web-unblock/'):
            self.assertEqual(self.client.get(API + path).status_code, 405)

    def test_every_alerted_public_ip_is_actionable_without_registration(self):
        threats = self.threats()
        self.assertEqual([(ip, threats[ip]['web_actionable'], threats[ip]['web_read_only_kind'])
                          for ip in (IP_A, IP_B, PROTECTED, LAB, SSH_TARGET, FIXTURE_IP)],
                         [(IP_A, True, ''), (IP_B, True, ''), (PROTECTED, False, 'allowlisted'), (LAB, False, 'not_public'),
                          (SSH_TARGET, False, 'not_public'), (FIXTURE_IP, False, 'fixture')])
        self.assertNotIn(UNALERTED, threats)
        # SSH block is separate: it needs an ssh_brute_force Alert, which the web-only IPs do not have.
        self.assertEqual((threats[IP_A]['actionable'], threats[SSH_TARGET]['actionable']), (False, True))
        data = self.client.get(API + 'threats/').json()
        self.assertEqual((data['web_block_enabled'], data['web_port'], data['web_private_ranges']), (True, '8080/tcp', []))
        self.assertNotIn('web_targets', data)

    def test_ip_a_and_ip_b_are_blocked_and_unblocked_independently(self):
        response, fake, from_settings = self.block(IP_A)
        self.assertEqual((response.status_code, response.json()['outcome'], response.json()['ufw_state']), (200, 'blocked', 'present'))
        self.assertEqual(fake.calls, [STATUS, cmd('block', IP_A), STATUS])
        from_settings.assert_called_once_with('RESPONSE_WEB_BLOCK_EXECUTE')

        # IP B while IP A is still listed: only IP B's state matters and only IP B is sent.
        response, fake, _ = self.block(IP_B, before=listed(IP_A), after=listed(IP_A, IP_B))
        self.assertEqual((response.json()['outcome'], fake.calls), ('blocked', [STATUS, cmd('block', IP_B), STATUS]))
        fake = ScriptedExecutor(out(stdout=listed(IP_A, IP_B)))
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
            states = self.post('web-status/').json()['states']
        self.assertEqual((states[IP_A], states[IP_B], states[PROTECTED]), ('present', 'present', 'absent'))

        response, fake, _ = self.unblock(IP_A, before=listed(IP_A, IP_B), after=listed(IP_B))
        self.assertEqual((response.json()['outcome'], fake.calls), ('unblocked', [STATUS, cmd('unblock', IP_A), STATUS]))
        response, fake, _ = self.act('web-block', [out(stdout=listed(IP_B))], ip=IP_B)
        self.assertEqual((response.json()['outcome'], fake.calls), ('already_blocked', [STATUS]))
        response, fake, _ = self.unblock(IP_B)
        self.assertEqual(response.json()['outcome'], 'unblocked')
        response, fake, _ = self.act('web-unblock', [out(stdout=OPEN)], ip=IP_B)
        self.assertEqual((response.json()['outcome'], fake.calls), ('already_unblocked', [STATUS]))

        records = WebBlockRecord.objects.order_by('id')
        self.assertEqual([(r.operation, r.target_ip, r.execution_status, r.state_before_result, r.state_after_result) for r in records],
                         [('block', IP_A, 'succeeded', 'absent', 'present'), ('block', IP_B, 'succeeded', 'absent', 'present'),
                          ('unblock', IP_A, 'succeeded', 'present', 'absent'), ('block', IP_B, 'skipped', 'present', 'present'),
                          ('unblock', IP_B, 'succeeded', 'present', 'absent'), ('unblock', IP_B, 'skipped', 'absent', 'absent')])
        self.assertEqual({r.requested_by for r in records}, {self.admin})
        self.assertEqual(records[1].command, f'sudo -n {HELPER} block {IP_B}')
        history = self.client.get(API + 'threats/').json()['history']
        self.assertEqual([(a['kind'], a['target_ip']) for a in history if a['scope'] == 'web'][:3],
                         [('web_unblock', IP_B), ('web_unblock', IP_B), ('web_block', IP_B)])
        threats = self.threats()
        self.assertEqual((threats[IP_A]['last_action']['kind'], threats[IP_B]['last_action']['execution_status']),
                         ('web_unblock', 'skipped'))
        # SSH evidence and Incidents are never written by the web actions.
        self.assertEqual((ResponseRecord.objects.count(), ManualBlockRecord.objects.count(),
                          UnblockRecord.objects.count(), Incident.objects.count()), (0, 0, 0, 0))

    def test_a_newly_alerted_ip_becomes_actionable_with_no_configuration_change(self):
        response, fake, _ = self.act('web-block', [], ip=IP_C)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (403, 'not_detected', []))
        self.assertNotIn(IP_C, self.threats())
        alert('nginx_scan', ip=IP_C)
        self.assertTrue(self.threats()[IP_C]['web_actionable'])
        response, fake, _ = self.block(IP_C)
        self.assertEqual((response.json()['outcome'], fake.calls[1]), ('blocked', cmd('block', IP_C)))
        response, _, _ = self.unblock(IP_C)
        self.assertEqual(response.json()['outcome'], 'unblocked')

    def test_refused_addresses_send_nothing_but_are_audited(self):
        for ip, kind in ((UNALERTED, 'not_detected'), (PROTECTED, 'allowlisted'), (FIXTURE_IP, 'fixture'),
                         ('1.2.3.4; reboot', 'invalid_ip'), ('../../etc/passwd', 'invalid_ip'), (SSH_TARGET, 'not_public'),
                         (LAB, 'not_public')):
            response, fake, _ = self.act('web-block', [], ip=ip)
            self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (FAILURE[kind], kind, []), ip)
        # Monitoring PC, mini PC, school WSL, loopback, link-local, reserved, multicast, unspecified, CGNAT:
        # refused even when an Alert exists for them.
        for ip, kind in (('172.18.20.65', 'not_public'), ('172.18.20.161', 'not_public'), ('172.29.176.40', 'not_public'),
                         ('127.0.0.1', 'fixture'), ('::1', 'fixture'), ('169.254.1.1', 'not_public'), ('fe80::1', 'not_public'),
                         ('240.0.0.1', 'not_public'), ('224.0.0.1', 'not_public'), ('0.0.0.0', 'not_public'),
                         ('100.64.0.1', 'not_public')):
            alert('nginx_scan', ip=ip)
            response, fake, _ = self.act('web-block', [], ip=ip)
            self.assertEqual((response.json()['failure_kind'], fake.calls), (kind, []), ip)
        self.assertTrue(WebBlockRecord.objects.exists())
        self.assertFalse(WebBlockRecord.objects.exclude(execution_status='failed').exists())

    def test_private_lab_range_is_explicit_and_never_covers_protected_or_special_addresses(self):
        with self.settings(RESPONSE_WEB_PRIVATE_RANGES='172.22.16.0/24'):
            self.assertTrue(self.threats()[LAB]['web_actionable'])
            response, fake, _ = self.block(LAB)
            self.assertEqual((response.json()['outcome'], fake.calls[1]), ('blocked', cmd('block', LAB)))
            self.assertEqual(self.threats()[SSH_TARGET]['web_read_only_kind'], 'not_public')  # outside the range
        with self.settings(RESPONSE_WEB_PRIVATE_RANGES='172.18.20.0/24'):  # the protected list still wins
            alert('nginx_scan', ip='172.18.20.65')
            response, fake, _ = self.act('web-block', [], ip='172.18.20.65')
            self.assertEqual((response.json()['failure_kind'], fake.calls), ('allowlisted', []))
        for bad in ('0.0.0.0/0', '8.8.8.0/24', '127.0.0.0/8', '169.254.0.0/16', 'not-a-cidr'):
            with self.settings(RESPONSE_WEB_PRIVATE_RANGES=bad):
                response, fake, _ = self.act('web-block', [], ip=LAB)
                self.assertEqual((response.json()['failure_kind'], fake.calls), ('config', []), bad)
                self.assertTrue(self.client.get(API + 'threats/').json()['web_config_error'])
                # A public IP does not depend on the private-range setting.
                response, _, _ = self.block(IP_A)
                self.assertEqual(response.json()['outcome'], 'blocked', bad)

    def test_the_requesting_administrators_own_address_is_never_blocked(self):
        response, fake, _ = self.act('web-block', [], ip=IP_B, REMOTE_ADDR=IP_B)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (403, 'self', []))
        self.assertEqual(self.threats(REMOTE_ADDR=IP_B)[IP_B]['web_read_only_kind'], 'self')
        self.assertTrue(self.threats()[IP_B]['web_actionable'])

    def test_unblock_ignores_protection_so_a_wrong_entry_can_be_released(self):
        with self.settings(RESPONSE_ALLOWLIST=IP_A):
            response, _, _ = self.act('web-block', [])
            self.assertEqual(response.json()['failure_kind'], 'allowlisted')
            self.assertTrue(self.threats()[IP_A]['web_unblock_allowed'])
            response, fake, _ = self.unblock(IP_A)
        self.assertEqual((response.json()['outcome'], fake.calls), ('unblocked', [STATUS, cmd('unblock', IP_A), STATUS]))
        response, fake, _ = self.act('web-unblock', [], ip=UNALERTED)  # still only alerted IPs
        self.assertEqual((response.json()['failure_kind'], fake.calls), ('not_detected', []))

    def test_confirm_and_ip_are_required_and_extra_input_is_ignored(self):
        for body in ({}, {'ip': IP_A}, {'ip': IP_A, 'confirm': 'yes'}, {'confirm': True}, [1]):
            for action in ('web-block', 'web-unblock'):
                response, fake, _ = self.act(action, [], body=body)
                self.assertEqual((response.status_code, fake.calls), (400, []))
        response, fake, _ = self.act('web-block', [out(stdout=OPEN), out(stdout='blocked\n'), out(stdout=listed(IP_A))],
                                     body={'ip': IP_A, 'confirm': True, 'command': 'sudo reboot', 'path': '/etc/passwd'})
        self.assertEqual((response.status_code, fake.calls), (200, [STATUS, cmd('block', IP_A), STATUS]))

    def test_status_read_failure_blocks_every_change(self):
        for action in ('web-block', 'web-unblock'):
            for script, kind in (([out(255, stderr='Connection refused')], 'ssh_error'),
                                 ([out(1, stderr='sudo: a password is required')], 'sudo_denied')):
                response, fake, _ = self.act(action, script)
                data = response.json()
                self.assertEqual((response.status_code, data['outcome'], data['failure_kind'], data['ufw_state']),
                                 (502, 'failed', kind, 'unchecked'))
                self.assertEqual(fake.calls, [STATUS])

    def test_command_failures_timeouts_and_rechecks(self):
        import subprocess
        response, _, _ = self.act('web-block', [out(stdout=OPEN), out(1, stderr='sudo: a password is required')])
        self.assertEqual((response.status_code, response.json()['failure_kind']), (502, 'sudo_denied'))
        response, _, _ = self.act('web-block', [out(stdout=OPEN), out(6, stderr='mini-soc-webblock: 1.1.1.1 is protected')])
        self.assertEqual(response.json()['failure_kind'], 'command_failed')
        response, _, _ = self.block(IP_A, after=OPEN)
        self.assertEqual(response.json()['failure_kind'], 'rule_not_present')
        response, _, _ = self.unblock(IP_A, after=listed(IP_A))
        self.assertEqual(response.json()['failure_kind'], 'rule_still_present')
        self.act('web-block', [out(stdout=OPEN), subprocess.TimeoutExpired('ssh', 30)])
        self.assertEqual(WebBlockRecord.objects.order_by('-id').first().execution_status, 'unknown')

    def test_switch_and_override_error_refuse_before_sending(self):
        with self.settings(RESPONSE_WEB_BLOCK_EXECUTE=False, RESPONSE_EXECUTE=True):
            response, fake, _ = self.act('web-block', [])
            self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (503, 'config', []))
            self.assertIn('RESPONSE_WEB_BLOCK_EXECUTE', response.json()['detail'])
            fake = ScriptedExecutor()
            with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
                data = self.post('web-status/').json()
            self.assertEqual((data['states'], data['failure_kind'], fake.calls), ({}, 'config', []))
        with self.settings(RESPONSE_OVERRIDES_ERROR='bad line'):
            response, fake, _ = self.act('web-block', [])
            self.assertEqual((response.json()['failure_kind'], fake.calls), ('config', []))
            self.assertEqual(self.client.get(API + 'threats/').json()['overrides_error'], 'bad line')

    def test_web_status_reads_once_and_ignores_garbage(self):
        fake = ScriptedExecutor(out(stdout=listed(IP_A) + 'garbage line\ndeny not-an-ip;\n'))
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
            data = self.post('web-status/').json()
        self.assertEqual((fake.calls, data['failure_kind']), ([STATUS], ''))
        self.assertEqual(data['states'], {IP_A: 'present', IP_B: 'absent', PROTECTED: 'absent', LAB: 'absent', SSH_TARGET: 'absent'})

    def test_http_check_is_recorded_separately(self):
        self.block(IP_A)
        record = WebBlockRecord.objects.get()
        call_command('record_web_check', record.pk, 403, evidence='curl -> 403', stdout=mock.MagicMock())
        record.refresh_from_db()
        self.assertEqual((record.http_check_status, record.http_check_result, record.execution_status), (403, 'success', 'succeeded'))
        call_command('record_web_check', record.pk, 200, evidence='curl -> 200 (still open)', stdout=mock.MagicMock())
        record.refresh_from_db()
        self.assertEqual(record.http_check_result, 'failed')
        self.unblock(IP_A)
        unblock = WebBlockRecord.objects.get(operation='unblock')
        call_command('record_web_check', unblock.pk, 200, evidence='curl -> 200', stdout=mock.MagicMock())
        unblock.refresh_from_db()
        self.assertEqual(unblock.http_check_result, 'success')
        self.act('web-block', [], ip=UNALERTED)
        with self.assertRaises(CommandError):
            call_command('record_web_check', WebBlockRecord.objects.get(target_ip=UNALERTED).pk, 403, evidence='x')


class ResponseOverrideTests(SimpleTestCase):
    def apply(self, text):
        namespace = {'RESPONSE_EXECUTE': True, 'RESPONSE_MANUAL_BLOCK_EXECUTE': True, 'RESPONSE_WEB_BLOCK_EXECUTE': True,
                     'RESPONSE_UNBLOCK_EXECUTE': True, 'RESPONSE_ALLOWLIST': '', 'RESPONSE_WEB_PRIVATE_RANGES': ''}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.response-overrides.env'
            if text is not None:
                path.write_text(text, encoding='utf-8')
            response_overrides.apply(namespace, path)
        return namespace

    def test_missing_file_changes_nothing(self):
        ns = self.apply(None)
        self.assertEqual((ns['RESPONSE_OVERRIDES_ERROR'], ns['RESPONSE_WEB_BLOCK_EXECUTE'], ns['RESPONSE_ALLOWLIST']), ('', True, ''))

    def test_allowed_keys_are_applied(self):
        ns = self.apply(f'# demo\nRESPONSE_ALLOWLIST=172.18.20.65,{PROTECTED}\nRESPONSE_WEB_PRIVATE_RANGES=172.22.16.0/24\n'
                        'RESPONSE_WEB_BLOCK_EXECUTE=false\n')
        self.assertEqual((ns['RESPONSE_ALLOWLIST'], ns['RESPONSE_WEB_PRIVATE_RANGES'], ns['RESPONSE_WEB_BLOCK_EXECUTE'], ns['RESPONSE_OVERRIDES_ERROR']),
                         (f'172.18.20.65,{PROTECTED}', '172.22.16.0/24', False, ''))
        self.assertTrue(ns['RESPONSE_MANUAL_BLOCK_EXECUTE'])

    def test_invalid_file_turns_every_block_switch_off(self):
        for text in ('RESPONSE_VICTIM_HOST=10.0.0.1\n', 'POSTGRES_PASSWORD=x\n', 'not a line\n',
                     'RESPONSE_WEB_BLOCK_EXECUTE=yes\n', 'RESPONSE_ALLOWLIST=1.1.1.1\nRESPONSE_ALLOWLIST=8.8.8.8\n',
                     f'RESPONSE_WEB_TARGETS={IP_A}\n'):
            ns = self.apply(text)
            self.assertTrue(ns['RESPONSE_OVERRIDES_ERROR'], text)
            self.assertEqual([ns[s] for s in response_overrides.BLOCK_SWITCHES],
                             [False] * len(response_overrides.BLOCK_SWITCHES), text)
            self.assertTrue(ns['RESPONSE_UNBLOCK_EXECUTE'])
            self.assertEqual(ns['RESPONSE_ALLOWLIST'], '')


class ResponseRefreshTests(TestCase):
    """refresh() re-reads the file onto live settings and reverts a removed key to its env default,
    so toggling RESPONSE_AUTO_WEB_EXECUTE off (by removing or setting the line) really takes effect."""

    def test_removing_a_key_reverts_it_to_the_env_default(self):
        import os
        from config import response_overrides
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.response-overrides.env'
            path.write_text('RESPONSE_AUTO_WEB_EXECUTE=true\n', encoding='utf-8')
            with override_settings(RESPONSE_OVERRIDES_FILE=str(path), RESPONSE_OVERRIDES_REFRESH=True,
                                   RESPONSE_AUTO_WEB_EXECUTE=False):
                with mock.patch.dict(os.environ, {'RESPONSE_AUTO_WEB_EXECUTE': ''}, clear=False):
                    response_overrides.refresh()
                    from django.conf import settings
                    self.assertTrue(settings.RESPONSE_AUTO_WEB_EXECUTE)  # file turned it on
                    # Operator removes the line to disable -> next refresh reverts to the env default (off).
                    path.write_text('# disabled\n', encoding='utf-8')
                    response_overrides.refresh()
                    self.assertFalse(settings.RESPONSE_AUTO_WEB_EXECUTE)
