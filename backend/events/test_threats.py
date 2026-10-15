import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from .models import Alert, ManualBlockRecord, ResponseRecord, ResponseVerification, UnblockRecord
from .test_response import ATTACKER as FIXTURE_IP, no_real_subprocess
from .test_unblock import UNBLOCK_ON, ScriptedExecutor, alert, block_record, out, snapshot

API = '/api/admin-panel/'
REAL, OTHER = '10.20.30.4', '10.20.30.9'
STATUS = ['sudo', '-n', 'ufw', 'status']
# The panel changes UFW only through the victim helper (deploy/victim/mini-soc-sshblock).
BLOCK = ['sudo', '-n', '/usr/local/sbin/mini-soc-sshblock', 'block', REAL]
DELETE = ['sudo', '-n', '/usr/local/sbin/mini-soc-sshblock', 'unblock', REAL]
HEAD = 'Status: active\n\nTo                         Action      From\n22/tcp                     ALLOW       Anywhere\n'
OPEN = HEAD
BLOCKED = HEAD + f'22/tcp                     DENY        {REAL}\n'
# REAL is a private lab attacker, so it needs an explicit /32; OTHER is outside it.
PANEL_ON = dict(UNBLOCK_ON, RESPONSE_MANUAL_BLOCK_EXECUTE=True, RESPONSE_SSH_PRIVATE_RANGES=f'{REAL}/32',
                RESPONSE_OVERRIDES_ERROR='')


@override_settings(**PANEL_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class ThreatPanelTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.admin = users.create_superuser('root', password='pw')
        self.staff = users.create_user('staff', password='pw', is_staff=True)
        for _ in range(3):
            alert(ip=REAL)
        alert('nginx_scan', ip=REAL)
        alert(ip=OTHER)
        alert(ip=FIXTURE_IP)
        self.client.force_login(self.admin)

    def post(self, path, body=None, client=None):
        return (client or self.client).post(API + path, json.dumps(body or {}), content_type='application/json')

    def act(self, action, script, ip=REAL, body=None):
        fake = ScriptedExecutor(*script)
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake) as from_settings:
            response = self.post(f'threats/{action}/', {'ip': ip, 'confirm': True} if body is None else body)
        return response, fake, from_settings

    def threats(self):
        return {t['ip']: t for t in self.client.get(API + 'threats/').json()['threats']}

    def records(self):
        return ManualBlockRecord.objects.count(), UnblockRecord.objects.count()

    def test_anonymous_and_non_superuser_are_denied(self):
        for client, status in ((Client(), 401), (Client(), 403)):
            if status == 403:
                client.force_login(self.staff)
            fake = ScriptedExecutor()
            with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
                statuses = [client.get(API + 'threats/').status_code, self.post('ufw-status/', client=client).status_code,
                            self.post('threats/block/', {'ip': REAL, 'confirm': True}, client).status_code,
                            self.post('threats/unblock/', {'ip': REAL, 'confirm': True}, client).status_code]
            self.assertEqual(statuses, [status] * 4)
            self.assertEqual((fake.calls, self.records()), ([], (0, 0)))

    def test_csrf_is_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        fake = ScriptedExecutor()
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
            statuses = [self.post(p, {'ip': REAL, 'confirm': True}, client).status_code
                        for p in ('ufw-status/', 'threats/block/', 'threats/unblock/')]
        self.assertEqual((statuses, fake.calls, self.records()), ([403] * 3, [], (0, 0)))
        for path in ('ufw-status/', 'threats/block/', 'threats/unblock/'):
            self.assertEqual(self.client.get(API + path).status_code, 405)

    def test_ip_list_is_deduplicated_and_aggregated(self):
        data = self.client.get(API + 'threats/').json()
        self.assertEqual(sorted(t['ip'] for t in data['threats']), sorted([REAL, OTHER, FIXTURE_IP]))
        real = self.threats()[REAL]
        self.assertEqual((real['alert_count'], real['rule_types']), (4, ['nginx_scan', 'ssh_brute_force']))
        self.assertEqual((real['has_past_block'], real['last_action'], real['incidents'], real['risk']), (False, None, [], None))
        self.assertNotIn('ufw_state', real)
        self.assertEqual((data['ssh_private_ranges'], data['manual_block_enabled'], data['unblock_enabled']), ([f'{REAL}/32'], True, True))

    def test_fixture_and_unapproved_ips_are_view_only(self):
        threats = self.threats()
        self.assertEqual([(threats[ip]['is_fixture'], threats[ip]['actionable'], threats[ip]['read_only_kind'])
                          for ip in (REAL, OTHER, FIXTURE_IP)],
                         [(False, True, ''), (False, False, 'not_public'), (True, False, 'fixture')])
        # A fixture address stays view-only even inside an allowed range.
        with self.settings(RESPONSE_SSH_PRIVATE_RANGES=f'{REAL}/32,192.0.2.0/24'):
            self.assertFalse(self.threats()[FIXTURE_IP]['actionable'])
            response, fake, _ = self.act('block', [], ip=FIXTURE_IP)
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (403, 'fixture', []))

    def test_unapproved_undetected_and_invalid_ips_are_refused(self):
        # Unblock needs a block made by this system instead of the address rules.
        for ip, block_kind, unblock_kind in ((OTHER, 'not_public', 'not_eligible'), ('10.9.9.9', 'not_public', 'not_eligible'),
                                             ('1.2.3.4; reboot', 'invalid_ip', 'invalid_ip')):
            for action, kind in (('block', block_kind), ('unblock', unblock_kind)):
                response, fake, _ = self.act(action, [], ip=ip)
                self.assertEqual((response.json()['failure_kind'], fake.calls), (kind, []), (ip, action))
                self.assertIn(response.status_code, (403, 409))
        with self.settings(RESPONSE_SSH_PRIVATE_RANGES='10.9.9.9/32'):  # allowed range but never detected
            response, fake, _ = self.act('block', [], ip='10.9.9.9')
        self.assertEqual((response.json()['failure_kind'], fake.calls), ('not_detected', []))
        with self.settings(RESPONSE_SSH_PRIVATE_RANGES='8.8.8.0/24'):  # a public range is not a private lab range
            response, fake, _ = self.act('block', [])
            self.assertEqual((response.json()['failure_kind'], fake.calls), ('config', []))
            self.assertFalse(self.threats()[REAL]['actionable'])
        with self.settings(RESPONSE_ALLOWLIST=REAL):
            response, fake, _ = self.act('block', [])
        self.assertEqual((response.json()['failure_kind'], fake.calls), ('allowlisted', []))
        self.assertEqual(UnblockRecord.objects.count(), 0)

    def test_confirm_and_ip_are_required_and_extra_input_is_ignored(self):
        for body in ({}, {'ip': REAL}, {'ip': REAL, 'confirm': 'yes'}, {'confirm': True}, [1]):
            for action in ('block', 'unblock'):
                response, fake, _ = self.act(action, [], body=body)
                self.assertEqual((response.status_code, fake.calls), (400, []))
        response, fake, _ = self.act('block', [out(stdout=OPEN), out(stdout='Rule inserted\n'), out(stdout=BLOCKED)],
                                     body={'ip': REAL, 'confirm': True, 'command': 'sudo reboot', 'port': 80})
        self.assertEqual((response.status_code, fake.calls), (200, [STATUS, BLOCK, STATUS]))

    def test_ufw_status_reads_once_for_real_ips_only(self):
        fake = ScriptedExecutor(out(stdout=BLOCKED))
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
            data = self.post('ufw-status/').json()
        self.assertEqual((fake.calls, data['states'], data['failure_kind']), ([STATUS], {REAL: 'present', OTHER: 'absent'}, ''))
        fake = ScriptedExecutor(out(255, stderr='Connection refused'))
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
            data = self.post('ufw-status/').json()
        self.assertEqual((data['states'], data['failure_kind']), ({}, 'ssh_error'))
        with self.settings(RESPONSE_UNBLOCK_EXECUTE=False, RESPONSE_MANUAL_BLOCK_EXECUTE=False):
            fake = ScriptedExecutor()
            with mock.patch('events.response.SshExecutor.from_settings', return_value=fake):
                data = self.post('ufw-status/').json()
        self.assertEqual((data['states'], data['failure_kind'], fake.calls), ({}, 'config', []))

    def test_block_unblock_reblock_cycle_keeps_all_history(self):
        past = block_record(ip=REAL)  # earlier automatic block, since unblocked on the victim
        verification = ResponseVerification.objects.create(response=past, ufw_rule_result='present', kali_ssh_reconnect_result='failed')
        before = snapshot(past)
        self.assertTrue(self.threats()[REAL]['has_past_block'])

        # 해제됨 -> 재차단: the past succeeded record does not stop a new manual block.
        response, fake, from_settings = self.act('block', [out(stdout=OPEN), out(stdout='Rule inserted\n'), out(stdout=BLOCKED)])
        data = response.json()
        self.assertEqual((response.status_code, data['outcome'], data['ufw_state']), (200, 'blocked', 'present'))
        self.assertEqual(fake.calls, [STATUS, BLOCK, STATUS])
        from_settings.assert_called_once_with('RESPONSE_MANUAL_BLOCK_EXECUTE')
        block = ManualBlockRecord.objects.get()
        self.assertEqual((block.requested_by, block.target_ip, block.execution_status, block.ufw_before_result, block.ufw_after_result),
                         (self.admin, REAL, 'succeeded', 'absent', 'present'))
        self.assertEqual(block.command, f'sudo -n /usr/local/sbin/mini-soc-sshblock block {REAL}')

        # 이미 차단된 IP: no duplicate rule.
        response, fake, _ = self.act('block', [out(stdout=BLOCKED)])
        self.assertEqual((response.status_code, response.json()['outcome'], fake.calls), (200, 'already_blocked', [STATUS]))

        # 차단 중 -> 해제: unblocks the newest block (the manual one) through the existing service.
        response, fake, from_settings = self.act('unblock', [out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN)])
        data = response.json()
        self.assertEqual((response.status_code, data['outcome'], data['ufw_state']), (200, 'unblocked', 'absent'))
        self.assertEqual(fake.calls, [STATUS, DELETE, STATUS])
        from_settings.assert_called_once_with('RESPONSE_UNBLOCK_EXECUTE')
        unblock = UnblockRecord.objects.get()
        self.assertEqual((unblock.manual_block, unblock.response, unblock.requested_by), (block, None, self.admin))

        # 해제됨 -> 다시 재차단.
        response, _, _ = self.act('block', [out(stdout=OPEN), out(stdout='Rule inserted\n'), out(stdout=BLOCKED)])
        self.assertEqual(response.json()['outcome'], 'blocked')

        self.assertEqual(list(ManualBlockRecord.objects.order_by('id').values_list('execution_status', flat=True)),
                         ['succeeded', 'skipped', 'succeeded'])
        self.assertEqual((snapshot(past), ResponseRecord.objects.count()), (before, 1))
        verification.refresh_from_db()
        self.assertEqual(verification.verification_status, 'success')
        data = self.client.get(API + 'threats/').json()
        self.assertEqual([(a['kind'], a['execution_status']) for a in data['history'] if a['target_ip'] == REAL][:4],
                         [('manual_block', 'succeeded'), ('unblock', 'succeeded'), ('manual_block', 'skipped'), ('manual_block', 'succeeded')])
        last = {t['ip']: t for t in data['threats']}[REAL]['last_action']
        self.assertEqual((last['kind'], last['requested_by'], last['ufw_before_result'], last['ufw_after_result']),
                         ('manual_block', 'root', 'absent', 'present'))

    def test_first_block_of_ip_without_history_then_unblock(self):
        self.assertFalse(self.threats()[REAL]['has_past_block'])
        response, fake, _ = self.act('unblock', [])
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (409, 'not_eligible', []))
        self.act('block', [out(stdout=OPEN), out(stdout='Rule inserted\n'), out(stdout=BLOCKED)])
        response, _, _ = self.act('unblock', [out(stdout=BLOCKED), out(stdout='Rule deleted\n'), out(stdout=OPEN)])
        self.assertEqual(response.json()['outcome'], 'unblocked')

    def test_status_read_failure_blocks_every_change(self):
        block_record(ip=REAL)
        for action in ('block', 'unblock'):
            for script, kind in (([out(255, stderr='Connection refused')], 'ssh_error'),
                                 ([out(1, stderr='sudo: a password is required')], 'sudo_denied')):
                response, fake, _ = self.act(action, script)
                data = response.json()
                self.assertEqual((response.status_code, data['outcome'], data['failure_kind'], data['ufw_state']),
                                 (502, 'failed', kind, 'unchecked'))
                self.assertEqual(fake.calls, [STATUS])  # the change command was never sent
        self.assertEqual(self.records(), (2, 2))  # refused attempts are still audited

    def test_block_failures_and_separate_switches(self):
        response, _, _ = self.act('block', [out(stdout=OPEN), out(1, stderr='sudo: a password is required')])
        self.assertEqual((response.status_code, response.json()['failure_kind']), (502, 'sudo_denied'))
        response, _, _ = self.act('block', [out(stdout=OPEN), out(stdout='Rule inserted\n'), out(stdout=OPEN)])
        self.assertEqual(response.json()['failure_kind'], 'rule_not_present')
        # Neither the automatic switch nor the unblock switch enables manual blocking.
        with self.settings(RESPONSE_MANUAL_BLOCK_EXECUTE=False, RESPONSE_EXECUTE=True, RESPONSE_UNBLOCK_EXECUTE=True):
            response, fake, _ = self.act('block', [])
        self.assertEqual((response.status_code, response.json()['failure_kind'], fake.calls), (503, 'config', []))
        self.assertIn('RESPONSE_MANUAL_BLOCK_EXECUTE', response.json()['detail'])
        self.assertEqual(Alert.objects.filter(source_ip=REAL).count(), 4)
