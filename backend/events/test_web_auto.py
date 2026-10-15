import tempfile
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from .models import Alert, ManualBlockRecord, ResponseRecord, WebBlockRecord
from .test_response import ATTACKER as FIXTURE_IP, no_real_subprocess
from .test_threats import PANEL_ON
from .test_unblock import ScriptedExecutor, alert, out
from .web_auto import active_auto_blocks, run_web_auto

IP_A, IP_B, PROTECTED = '118.235.65.6', '1.1.1.1', '119.194.231.131'
HELPER = '/usr/local/sbin/mini-soc-webblock'
STATUS = ['sudo', '-n', HELPER, 'status']
OPEN = '# mini-soc web blocklist (Nginx 8080)\n'


def cmd(op, ip):
    return ['sudo', '-n', HELPER, op, ip]


def listed(*ips):
    return OPEN + ''.join(f'deny {ip};\n' for ip in ips)


# Auto block ON, web executor ON (TTL unblock), both the SSH manual settings from PANEL_ON present.
AUTO_ON = dict(PANEL_ON, RESPONSE_WEB_BLOCK_EXECUTE=True, RESPONSE_AUTO_WEB_EXECUTE=True,
               RESPONSE_WEB_PRIVATE_RANGES='', RESPONSE_ALLOWLIST=f'172.18.20.65,{PROTECTED}',
               RESPONSE_AUTO_WEB_MAX_ALERT_AGE=300, RESPONSE_AUTO_WEB_HOURLY_LIMIT=3, RESPONSE_AUTO_WEB_TTL=600)


@override_settings(**AUTO_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class WebAutoPlaybookTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser('root', password='pw')

    def scan(self, ip):
        return alert('nginx_scan', ip=ip)

    def run_with(self, *script, now=None):
        # Let web_action build its executor via from_settings so the gating switch name is exercised.
        fake = ScriptedExecutor(*script)
        with mock.patch('events.response.SshExecutor.from_settings', return_value=fake) as from_settings:
            summary = run_web_auto(now=now)
        return summary, fake, from_settings

    def test_disabled_by_default_sends_nothing(self):
        self.scan(IP_A)
        with self.settings(RESPONSE_AUTO_WEB_EXECUTE=False):
            summary, fake, _ = self.run_with()
        self.assertEqual((summary['block'], fake.calls, WebBlockRecord.objects.count()), ({'enabled': False}, [], 0))

    def test_recent_nginx_scan_is_auto_blocked_once_with_ttl(self):
        a = self.scan(IP_A)
        now = timezone.now()
        summary, fake, from_settings = self.run_with(out(stdout=OPEN), out(stdout='blocked\n'), out(stdout=listed(IP_A)), now=now)
        self.assertEqual(summary['block'], {'enabled': True, 'blocked': 1, 'skipped': 0, 'failed': 0, 'rate_limited': 0})
        self.assertEqual(fake.calls, [STATUS, cmd('block', IP_A), STATUS])
        from_settings.assert_called_once_with('RESPONSE_AUTO_WEB_EXECUTE')
        rec = WebBlockRecord.objects.get()
        self.assertEqual((rec.origin, rec.operation, rec.target_ip, rec.execution_status, rec.trigger_alert_id, rec.requested_by),
                         ('auto', 'block', IP_A, 'succeeded', a.pk, None))
        self.assertEqual(rec.requested_by_username, 'auto')
        self.assertAlmostEqual((rec.expires_at - now).total_seconds(), 600, delta=5)

        # Idempotent: the same Alert is not handled again, and no second command is sent.
        summary, fake, _ = self.run_with(out(stdout=listed(IP_A)))
        self.assertEqual((summary['block']['blocked'], fake.calls), (0, []))
        self.assertEqual(WebBlockRecord.objects.filter(operation='block').count(), 1)

    def test_old_alerts_are_not_bulk_blocked_at_activation(self):
        a = self.scan(IP_A)
        Alert.objects.filter(pk=a.pk).update(created_at=timezone.now() - timedelta(seconds=600))
        summary, fake, _ = self.run_with()
        self.assertEqual((summary['block']['blocked'], fake.calls, WebBlockRecord.objects.count()), (0, [], 0))

    def test_protected_and_fixture_and_nonscan_are_never_auto_blocked(self):
        self.scan(PROTECTED)
        self.scan('172.18.20.65')
        self.scan(FIXTURE_IP)
        alert('nginx_suspicious_path', ip=IP_B)  # not the trigger rule
        alert(ip=IP_B)  # ssh_brute_force, not the trigger rule
        summary, fake, _ = self.run_with()
        self.assertEqual(fake.calls, [])
        # Protected / fixture scans are recorded (handled, not retried) but never sent.
        kinds = dict(WebBlockRecord.objects.values_list('target_ip', 'failure_kind'))
        self.assertEqual((kinds.get(PROTECTED), kinds.get('172.18.20.65'), kinds.get(FIXTURE_IP)),
                         ('allowlisted', 'not_public', 'fixture'))
        self.assertFalse(WebBlockRecord.objects.filter(target_ip=IP_B).exists())
        self.assertEqual(summary['block']['blocked'], 0)

    def test_hourly_limit_caps_automatic_blocks(self):
        ips = ['8.8.8.8', '9.9.9.9', '1.0.0.1', '1.2.4.8']
        for ip in ips:
            self.scan(ip)  # created oldest-first in list order
        script = []
        for ip in ips[:3]:
            script += [out(stdout=OPEN), out(stdout='blocked\n'), out(stdout=listed(ip))]
        summary, fake, _ = self.run_with(*script)
        self.assertEqual(summary['block'], {'enabled': True, 'blocked': 3, 'skipped': 0, 'failed': 0, 'rate_limited': 1})
        self.assertEqual(fake.calls.count(STATUS), 6)  # 3 blocks x (status, block, status) = 9 calls, 6 are status
        limited = WebBlockRecord.objects.get(failure_kind='rate_limited')
        self.assertEqual((limited.target_ip, limited.execution_status, limited.trigger_alert_id is not None), (ips[3], 'skipped', True))
        # The 4th stays handled: a later cycle does not retry it.
        summary, fake, _ = self.run_with()
        self.assertEqual((summary['block']['blocked'], fake.calls), (0, []))

    def test_crash_before_record_is_not_a_duplicate_rule_next_cycle(self):
        # Alert handled by nobody yet, but the rule is already present on the victim (prior crashed send).
        self.scan(IP_A)
        summary, fake, _ = self.run_with(out(stdout=listed(IP_A)))
        self.assertEqual((summary['block']['skipped'], fake.calls), (1, [STATUS]))
        rec = WebBlockRecord.objects.get()
        self.assertEqual((rec.execution_status, rec.operation), ('skipped', 'block'))

    def _make_auto_block(self, ip, ttl_offset):
        """A succeeded auto block whose TTL is `ttl_offset` from now (negative = already expired)."""
        now = timezone.now()
        return WebBlockRecord.objects.create(
            operation='block', origin='auto', trigger_alert=self.scan(ip), requested_by_username='auto',
            target_ip=ip, execution_status='succeeded', state_after_result='present',
            executed_at=now - timedelta(seconds=700), expires_at=now + timedelta(seconds=ttl_offset))

    def test_expired_auto_block_is_auto_unblocked_even_when_auto_switch_is_off(self):
        self._make_auto_block(IP_A, ttl_offset=-60)
        with self.settings(RESPONSE_AUTO_WEB_EXECUTE=False):  # auto OFF, web executor still ON
            summary, fake, from_settings = self.run_with(out(stdout=listed(IP_A)), out(stdout='unblocked\n'), out(stdout=OPEN))
        self.assertEqual(summary['expire'], {'due': 1, 'unblocked': 1, 'failed': 0, 'deferred': 0})
        self.assertEqual(fake.calls, [STATUS, cmd('unblock', IP_A), STATUS])
        from_settings.assert_called_once_with('RESPONSE_WEB_BLOCK_EXECUTE')
        self.assertEqual(active_auto_blocks(), [])  # released

    def test_unexpired_auto_block_is_left_alone(self):
        self._make_auto_block(IP_A, ttl_offset=+300)
        summary, fake, _ = self.run_with()
        self.assertEqual((summary['expire']['due'], fake.calls), (0, []))

    def test_ttl_does_not_touch_an_ip_a_manual_block_took_over(self):
        block = self._make_auto_block(IP_A, ttl_offset=-60)
        ManualBlockRecord.objects.create(  # admin re-blocked later; they own it now
            requested_by=self.admin, requested_by_username='root', target_ip=IP_A, execution_status='succeeded',
            executed_at=block.executed_at + timedelta(seconds=10))
        # active_auto_blocks only tracks WebBlockRecord; the manual SSH block does not change web state,
        # so for the WEB blocklist the auto block is still the latest WEB block. Guard via a later web block.
        WebBlockRecord.objects.create(operation='block', origin='manual', requested_by_username='root',
                                      target_ip=IP_A, execution_status='succeeded',
                                      executed_at=block.executed_at + timedelta(seconds=20), state_after_result='present')
        summary, fake, _ = self.run_with()
        self.assertEqual((summary['expire']['due'], fake.calls), (0, []))

    def test_manual_unblock_stops_the_ttl_from_double_unblocking(self):
        block = self._make_auto_block(IP_A, ttl_offset=-60)  # expired auto block
        # An administrator unblocked it manually (origin='manual') after the block.
        WebBlockRecord.objects.create(operation='unblock', origin='manual', requested_by=self.admin,
            requested_by_username='root', target_ip=IP_A, execution_status='succeeded', state_after_result='absent',
            executed_at=block.executed_at + timedelta(seconds=30))
        self.assertEqual(active_auto_blocks(), [])  # already released
        summary, fake, _ = self.run_with()
        self.assertEqual((summary['expire']['due'], summary['expire']['unblocked'], fake.calls), (0, 0, []))

    def test_expiry_is_deferred_when_web_executor_is_off(self):
        self._make_auto_block(IP_A, ttl_offset=-60)
        with self.settings(RESPONSE_WEB_BLOCK_EXECUTE=False, RESPONSE_AUTO_WEB_EXECUTE=False):
            summary, fake, _ = self.run_with()
        self.assertEqual((summary['expire'], fake.calls), ({'due': 1, 'unblocked': 0, 'failed': 0, 'deferred': 1}, []))

    def test_a_broken_override_file_turns_the_block_phase_off_before_sending(self):
        self.scan(IP_A)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / '.response-overrides.env'
            bad.write_text('this is not a valid line\n', encoding='utf-8')
            with self.settings(RESPONSE_OVERRIDES_FILE=str(bad), RESPONSE_OVERRIDES_REFRESH=True):
                summary, fake, _ = self.run_with()
        # refresh() turns every block switch (incl. the auto switch) off, so the block phase never runs.
        self.assertEqual((summary['block'], fake.calls, WebBlockRecord.objects.count()), ({'enabled': False}, [], 0))

    def test_ssh_and_response_records_are_untouched(self):
        self.scan(IP_A)
        self.run_with(out(stdout=OPEN), out(stdout='blocked\n'), out(stdout=listed(IP_A)))
        self.assertEqual((ResponseRecord.objects.count(), ManualBlockRecord.objects.count()), (0, 0))


@override_settings(**AUTO_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class WebAutoApiShapeTests(TestCase):
    """The read-only /api/responses/web-auto/ contract the SOAR console renders."""

    def test_counts_and_cases_pair_block_with_its_ttl_unblock(self):
        from django.test import Client
        a = alert('nginx_scan', ip=IP_A)
        block = WebBlockRecord.objects.create(
            operation='block', origin='auto', trigger_alert=a, requested_by_username='auto', target_ip=IP_A,
            execution_status='succeeded', state_after_result='present', http_check_status=403, http_check_result='success',
            executed_at=timezone.now() - timedelta(seconds=600), expires_at=timezone.now() - timedelta(seconds=1))
        unblock = WebBlockRecord.objects.create(
            operation='unblock', origin='auto', trigger_alert=a, requested_by_username='auto', target_ip=IP_A,
            execution_status='succeeded', state_after_result='absent', http_check_status=200, http_check_result='success',
            executed_at=timezone.now())
        d = Client(HTTP_HOST='localhost').get('/api/responses/web-auto/').json()
        self.assertEqual((d['enabled'], d['counts']['blocks_succeeded'], d['counts']['http_verified'],
                          d['counts']['unblocks_succeeded'], d['counts']['active']), (True, 1, 1, 1, 0))
        self.assertEqual(len(d['cases']), 1)
        c = d['cases'][0]
        self.assertEqual((c['target_ip'], c['alert']['id'], c['block']['id'], c['unblock']['id']),
                         (IP_A, a.pk, block.pk, unblock.pk))
        self.assertEqual((c['block']['http_check_result'], c['unblock']['http_check_status']), ('success', 200))

    def test_block_still_active_has_no_unblock_in_its_case(self):
        from django.test import Client
        a = alert('nginx_scan', ip=IP_B)
        WebBlockRecord.objects.create(operation='block', origin='auto', trigger_alert=a, requested_by_username='auto',
            target_ip=IP_B, execution_status='succeeded', state_after_result='present',
            executed_at=timezone.now(), expires_at=timezone.now() + timedelta(seconds=600))
        d = Client(HTTP_HOST='localhost').get('/api/responses/web-auto/').json()
        c = next(c for c in d['cases'] if c['target_ip'] == IP_B)
        self.assertIsNone(c['unblock'])
        self.assertEqual((d['counts']['active'], c['block']['http_check_status']), (1, None))
