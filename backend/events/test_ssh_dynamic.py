import json
from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings

from .models import Incident, ManualBlockRecord, ResponseRecord, UnblockRecord, WebBlockRecord
from .response import block_command, respond_to_alert
from .test_response import no_real_subprocess
from .test_unblock import UNBLOCK_ON, ScriptedExecutor, alert, out
from .unblock import unblock_command, unblock_response

API = '/api/admin-panel/'
# Any IP with an ssh_brute_force Alert is a target; nothing is pre-registered. SSH_C is alerted mid-test.
SSH_A, SSH_B, SSH_C = '211.234.10.20', '175.223.1.2', '2001:4860:4860::8888'
WEB_ONLY, PROTECTED, LAB = '1.1.1.1', '119.194.231.131', '172.18.20.123'
HELPER = '/usr/local/sbin/mini-soc-sshblock'
STATUS = ['sudo', '-n', 'ufw', 'status']
HEAD = 'Status: active\n\nTo                         Action      From\n--                         ------      ----\n'


def cmd(operation, ip):
    return ['sudo', '-n', HELPER, operation, ip]


def ufw(*ips):
    """`ufw status` with a 22/tcp DENY line per IP (v6 lines as UFW prints them) plus an unrelated rule."""
    lines = [f'22/tcp{" (v6)" if ":" in ip else ""}                     DENY        {ip}' for ip in ips]
    return HEAD + ''.join(f'{line}\n' for line in lines) + '22/tcp                     ALLOW       172.18.20.0/24\n'


SSH_ON = dict(UNBLOCK_ON, RESPONSE_MANUAL_BLOCK_EXECUTE=True, RESPONSE_SSH_PRIVATE_RANGES='', RESPONSE_OVERRIDES_ERROR='',
              RESPONSE_WEB_BLOCK_EXECUTE=True, RESPONSE_WEB_PRIVATE_RANGES='',
              RESPONSE_ALLOWLIST=f'172.18.20.65,172.18.20.161,172.29.176.40,{PROTECTED}')


@override_settings(**SSH_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class DynamicSshBlockTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser('root', password='pw')
        for ip in (SSH_A, SSH_B, PROTECTED, LAB):
            alert(ip=ip)  # ssh_brute_force
        alert('nginx_scan', ip=SSH_A)
        alert('nginx_scan', ip=WEB_ONLY)
        alert('nginx_suspicious_path', ip=WEB_ONLY)
        self.client.force_login(self.admin)

    def act(self, action, script, ip, **extra):
        fake = ScriptedExecutor(*script)
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake) as from_settings:
            response = self.client.post(API + f'threats/{action}/', json.dumps({'ip': ip, 'confirm': True}),
                                        content_type='application/json', **extra)
        return response, fake, from_settings

    def block(self, ip, before=None, after=None):
        return self.act('block', [out(stdout=before or ufw()), out(stdout=f'{ip} blocked on 22/tcp\n'),
                                  out(stdout=after or ufw(ip))], ip)

    def unblock(self, ip, before=None, after=None):
        return self.act('unblock', [out(stdout=before or ufw(ip)), out(stdout=f'{ip} unblocked on 22/tcp\n'),
                                    out(stdout=after or ufw())], ip)

    def threats(self, **extra):
        return {t['ip']: t for t in self.client.get(API + 'threats/', **extra).json()['threats']}

    def test_ip_a_and_ip_b_are_ssh_blocked_and_unblocked_independently(self):
        response, fake, from_settings = self.block(SSH_A)
        self.assertEqual((response.status_code, response.json()['outcome']), (200, 'blocked'))
        self.assertEqual(fake.calls, [STATUS, cmd('block', SSH_A), STATUS])
        from_settings.assert_called_once_with('RESPONSE_MANUAL_BLOCK_EXECUTE')

        response, fake, _ = self.block(SSH_B, before=ufw(SSH_A), after=ufw(SSH_A, SSH_B))
        self.assertEqual((response.json()['outcome'], fake.calls), ('blocked', [STATUS, cmd('block', SSH_B), STATUS]))
        response, fake, _ = self.act('block', [out(stdout=ufw(SSH_A, SSH_B))], SSH_B)
        self.assertEqual((response.json()['outcome'], fake.calls), ('already_blocked', [STATUS]))

        response, fake, from_settings = self.unblock(SSH_A, before=ufw(SSH_A, SSH_B), after=ufw(SSH_B))
        self.assertEqual((response.json()['outcome'], fake.calls), ('unblocked', [STATUS, cmd('unblock', SSH_A), STATUS]))
        from_settings.assert_called_once_with('RESPONSE_UNBLOCK_EXECUTE')
        response, _, _ = self.unblock(SSH_B)
        self.assertEqual(response.json()['outcome'], 'unblocked')

        blocks = {b.target_ip: b for b in ManualBlockRecord.objects.filter(execution_status='succeeded')}
        self.assertEqual({ip: (b.command, b.requested_by) for ip, b in blocks.items()},
                         {ip: (f'sudo -n {HELPER} block {ip}', self.admin) for ip in (SSH_A, SSH_B)})
        unblocks = UnblockRecord.objects.order_by('id')
        self.assertEqual([(u.target_ip, u.manual_block_id, u.command, u.ufw_before_result, u.ufw_after_result) for u in unblocks],
                         [(SSH_A, blocks[SSH_A].pk, f'sudo -n {HELPER} unblock {SSH_A}', 'present', 'absent'),
                          (SSH_B, blocks[SSH_B].pk, f'sudo -n {HELPER} unblock {SSH_B}', 'present', 'absent')])
        # Web records, automatic responses and Incidents are never touched by SSH actions.
        self.assertEqual((WebBlockRecord.objects.count(), ResponseRecord.objects.count(), Incident.objects.count()), (0, 0, 0))

    def test_a_newly_alerted_ipv6_attacker_needs_no_configuration_change(self):
        response, fake, _ = self.act('block', [], SSH_C)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (403, 'not_detected', []))
        alert(ip=SSH_C)
        self.assertTrue(self.threats()[SSH_C]['actionable'])
        response, fake, _ = self.block(SSH_C)
        self.assertEqual((response.json()['outcome'], fake.calls[1]), ('blocked', cmd('block', SSH_C)))
        response, _, _ = self.unblock(SSH_C)
        self.assertEqual(response.json()['outcome'], 'unblocked')

    def test_nginx_only_attacker_is_not_an_ssh_target_but_stays_web_blockable(self):
        threats = self.threats()
        self.assertEqual((threats[WEB_ONLY]['actionable'], threats[WEB_ONLY]['read_only_kind'], threats[WEB_ONLY]['web_actionable']),
                         (False, 'not_detected', True))
        self.assertTrue(threats[SSH_A]['actionable'] and threats[SSH_A]['web_actionable'])
        response, fake, _ = self.act('block', [], WEB_ONLY)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (403, 'not_detected', []))
        self.assertIn('ssh_brute_force', response.json()['detail'])

    def test_protected_special_private_and_own_addresses_are_refused(self):
        cases = [(PROTECTED, 'allowlisted'), (LAB, 'not_public')]
        for ip in ('172.18.20.65', '172.18.20.161', '172.29.176.40', '169.254.1.1', 'fe80::1', '240.0.0.1',
                   '224.0.0.1', '0.0.0.0', '100.64.0.1', '10.0.0.1'):
            alert(ip=ip)
            cases.append((ip, 'not_public'))
        alert(ip='127.0.0.1')
        cases += [('127.0.0.1', 'fixture'), ('1.2.3.4; ufw disable', 'invalid_ip'), ('any', 'invalid_ip')]
        for ip, kind in cases:
            response, fake, _ = self.act('block', [], ip)
            self.assertEqual((response.json()['failure_kind'], fake.calls), (kind, []), ip)
        response, fake, _ = self.act('block', [], SSH_B, REMOTE_ADDR=SSH_B)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (403, 'self', []))
        self.assertEqual(self.threats(REMOTE_ADDR=SSH_B)[SSH_B]['read_only_kind'], 'self')
        self.assertFalse(ManualBlockRecord.objects.exclude(execution_status='failed').exists())

    def test_private_lab_needs_an_explicit_range_and_protection_still_wins(self):
        with self.settings(RESPONSE_SSH_PRIVATE_RANGES=f'{LAB}/32'):
            self.assertTrue(self.threats()[LAB]['actionable'])
            response, fake, _ = self.block(LAB)
            self.assertEqual((response.json()['outcome'], fake.calls[1]), ('blocked', cmd('block', LAB)))
        alert(ip='172.18.20.65')
        with self.settings(RESPONSE_SSH_PRIVATE_RANGES='172.18.20.0/24'):
            response, fake, _ = self.act('block', [], '172.18.20.65')
        self.assertEqual((response.json()['failure_kind'], fake.calls), ('allowlisted', []))
        # The web range does not open SSH, and vice versa.
        with self.settings(RESPONSE_WEB_PRIVATE_RANGES=f'{LAB}/32'):
            self.assertEqual(self.threats()[LAB]['read_only_kind'], 'not_public')

    def test_unblock_only_removes_blocks_this_system_made(self):
        # A matching rule made by hand on the victim is never removed from the panel.
        response, fake, _ = self.act('unblock', [], SSH_B)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (409, 'not_eligible', []))
        self.assertFalse(self.threats()[SSH_B]['ssh_unblock_allowed'])
        # A block this system made can be released even after the IP becomes protected.
        self.block(SSH_A)
        with self.settings(RESPONSE_ALLOWLIST=SSH_A):
            threat = self.threats()[SSH_A]
            self.assertEqual((threat['actionable'], threat['ssh_unblock_allowed']), (False, True))
            response, fake, _ = self.unblock(SSH_A)
        self.assertEqual((response.json()['outcome'], fake.calls[1]), ('unblocked', cmd('unblock', SSH_A)))

    def test_switch_and_override_error_refuse_before_sending(self):
        with self.settings(RESPONSE_MANUAL_BLOCK_EXECUTE=False, RESPONSE_EXECUTE=True, RESPONSE_WEB_BLOCK_EXECUTE=True):
            response, fake, _ = self.act('block', [], SSH_A)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (503, 'config', []))
        with self.settings(RESPONSE_OVERRIDES_ERROR='bad line'):
            response, fake, _ = self.act('block', [], SSH_A)
        self.assertEqual((response.json()['failure_kind'], fake.calls), ('config', []))
        with self.settings(RESPONSE_SSH_PRIVATE_RANGES='0.0.0.0/0'):
            data = self.client.get(API + 'threats/').json()
            self.assertTrue(data['config_error'])
            response, fake, _ = self.act('block', [], LAB)
        self.assertEqual((response.json()['failure_kind'], fake.calls), ('config', []))

    def test_helper_failures_are_recorded_and_not_reported_as_blocked(self):
        response, _, _ = self.act('block', [out(stdout=ufw()), out(9, stderr='mini-soc-sshblock: UFW is not active')], SSH_A)
        self.assertEqual((response.status_code, response.json()['failure_kind']), (502, 'command_failed'))
        response, _, _ = self.act('block', [out(stdout=ufw()), out(1, stderr='sudo: a password is required')], SSH_A)
        self.assertEqual(response.json()['failure_kind'], 'sudo_denied')
        response, _, _ = self.block(SSH_A, after=ufw())
        self.assertEqual(response.json()['failure_kind'], 'rule_not_present')
        response, _, _ = self.act('block', [out(255, stderr='Connection timed out')], SSH_A)
        self.assertEqual((response.json()['failure_kind'], response.json()['ufw_state']), ('ssh_error', 'unchecked'))

    def test_reconnect_check_is_recorded_separately_from_the_command(self):
        self.block(SSH_A)
        block = ManualBlockRecord.objects.get(execution_status='succeeded')
        self.assertEqual(block.kali_ssh_reconnect_result, 'unchecked')
        stdout = StringIO()
        call_command('record_ssh_check', 'block', block.pk, 'failed', evidence='nc -vz -w 5 ... timed out', stdout=stdout)
        block.refresh_from_db()
        self.assertEqual((block.kali_ssh_reconnect_result, block.execution_status), ('failed', 'succeeded'))
        self.assertIsNotNone(block.reconnect_checked_at)
        self.assertIn('-> verified', stdout.getvalue())
        self.unblock(SSH_A)
        unblock = UnblockRecord.objects.get()
        stdout = StringIO()
        call_command('record_ssh_check', 'unblock', unblock.pk, 'failed', evidence='still timed out', stdout=stdout)
        self.assertIn('not verified', stdout.getvalue())
        history = self.client.get(API + 'threats/').json()['history']
        self.assertEqual([(a['kind'], a['reconnect_result']) for a in history if a['target_ip'] == SSH_A][:2],
                         [('unblock', 'failed'), ('manual_block', 'failed')])
        self.act('block', [], WEB_ONLY)
        refused = ManualBlockRecord.objects.get(target_ip=WEB_ONLY)
        with self.assertRaises(CommandError):
            call_command('record_ssh_check', 'block', refused.pk, 'failed', evidence='x')

    def test_automatic_response_and_django_admin_unblock_keep_direct_ufw_commands(self):
        from .test_response import FakeExecutor
        fake = FakeExecutor()
        with self.settings(RESPONSE_EXECUTE=True):
            record, _ = respond_to_alert(alert(ip='58.120.1.1'), executor=fake)
        self.assertEqual(fake.calls, [block_command('58.120.1.1')])
        self.assertEqual(fake.calls[0][:4], ['sudo', '-n', 'ufw', 'prepend'])
        fake = ScriptedExecutor(out(stdout=ufw('58.120.1.1')), out(stdout='Rule deleted\n'), out(stdout=ufw()))
        audit = unblock_response(record, self.admin, executor=fake)
        self.assertEqual((audit.execution_status, fake.calls[1]), ('succeeded', unblock_command('58.120.1.1')))
