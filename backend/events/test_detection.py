from datetime import datetime, timedelta, timezone
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from rest_framework.test import APIClient

from .detection import is_suspicious_path, run_detection
from .models import Alert, SecurityEvent

BASE = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone(timedelta(hours=9)))
ATTACKER = '192.0.2.50'


def ssh(seconds, result='failure', ip=ATTACKER):
    return SecurityEvent.objects.create(
        source_type='ssh', event_time=BASE + timedelta(seconds=seconds), source_ip=ip,
        action='ssh_login', result=result, ssh_evidence='controlled', raw_log='controlled ssh',
    )


def nginx(seconds, path, status=404, ip=ATTACKER):
    return SecurityEvent.objects.create(
        source_type='nginx', event_time=BASE + timedelta(seconds=seconds), source_ip=ip,
        action='GET', result=str(status), request_path=path, http_status=status,
        raw_log='controlled nginx',
    )


class SshBruteForceTests(TestCase):
    def test_five_failures_within_60s_alert(self):
        events = [ssh(s) for s in (0, 10, 20, 30, 60)]
        self.assertEqual(run_detection(), 1)
        alert = Alert.objects.get()
        self.assertEqual(alert.rule_type, 'ssh_brute_force')
        self.assertEqual(alert.source_ip, ATTACKER)
        self.assertEqual(alert.occurred_at, events[-1].event_time)
        self.assertEqual(alert.trigger_event, events[-1])
        self.assertEqual(set(alert.related_events.all()), set(events))
        self.assertIn('5 SSH authentication failures', alert.evidence)

    def test_below_threshold_spread_or_mixed_does_not_alert(self):
        for s in (0, 10, 20, 30):
            ssh(s)                              # only 4 failures in the window
        ssh(40, result='success')               # success is not counted
        ssh(45, ip='198.51.100.9')              # different IP
        ssh(61)                                 # 5th failure but 61s after the first
        self.assertEqual(run_detection(), 0)
        self.assertFalse(Alert.objects.exists())


class NginxScanTests(TestCase):
    def test_ten_distinct_403_404_paths_within_60s_alert(self):
        events = [nginx(i * 6, f'/probe{i}', 403 if i % 2 else 404) for i in range(10)]
        self.assertEqual(run_detection(), 1)
        alert = Alert.objects.get()
        self.assertEqual(alert.rule_type, 'nginx_scan')
        self.assertEqual(alert.trigger_event, events[-1])
        self.assertEqual(alert.related_events.count(), 10)

    def test_repeated_paths_other_status_or_slow_does_not_alert(self):
        for i in range(9):
            nginx(i, f'/probe{i}')
        nginx(10, '/probe0')                    # repeat does not add a distinct path
        nginx(11, '/ok-page', status=200)       # non-403/404 status is ignored
        nginx(12, '/probe9', ip='198.51.100.9') # different IP
        nginx(70, '/probe9')                    # 10th distinct path but outside 60s of the first
        self.assertEqual(run_detection(), 0)


class NginxSuspiciousPathTests(TestCase):
    def test_exact_and_sub_paths_alert(self):
        nginx(0, '/admin', status=200)
        nginx(1, '/admin/users', status=403)
        nginx(2, '/.env')
        self.assertEqual(run_detection(), 3)
        self.assertEqual(set(Alert.objects.values_list('rule_type', flat=True)), {'nginx_suspicious_path'})
        self.assertEqual(
            sorted(a.related_events.get().request_path for a in Alert.objects.all()),
            ['/.env', '/admin', '/admin/users'],
        )

    def test_lookalike_paths_do_not_alert(self):
        for i, path in enumerate(('/administrator', '/wp-login.php.bak', '/configs', '/')):
            nginx(i * 30, path, status=200)
        self.assertEqual(run_detection(), 0)

    def test_matcher(self):
        for path in ('/.git', '/.git/config', '/wp-admin/', '/backup/db.sql', '/phpmyadmin'):
            self.assertTrue(is_suspicious_path(path), path)
        for path in ('/.github', '/backups', '/wp-admin-x', '/x/admin'):
            self.assertFalse(is_suspicious_path(path), path)


class DetectionRunTests(TestCase):
    def test_rerun_does_not_duplicate_and_continues(self):
        for s in range(5):
            ssh(s)
        call_command('run_detection', stdout=StringIO())
        call_command('run_detection', stdout=StringIO())
        self.assertEqual(Alert.objects.count(), 1)
        for s in range(5, 9):
            ssh(s)                              # 4 more failures: window restarted, below threshold
        self.assertEqual(run_detection(), 0)
        ssh(9)
        self.assertEqual(run_detection(), 1)
        self.assertEqual(Alert.objects.count(), 2)


class AlertApiTests(TestCase):
    def test_read_only_list_and_detail(self):
        client = APIClient()
        self.assertEqual(client.get('/api/alerts/').json(), [])
        self.assertEqual(client.get('/api/alerts/1/').status_code, 404)
        event = nginx(0, '/wp-login.php', status=200)
        run_detection()
        alert = Alert.objects.get()
        detail = client.get(f'/api/alerts/{alert.pk}/').json()
        self.assertEqual(client.get('/api/alerts/').json(), [detail])
        self.assertEqual(detail['rule_type'], 'nginx_suspicious_path')
        self.assertEqual(detail['source_ip'], ATTACKER)
        self.assertEqual(detail['related_event_ids'], [event.pk])
        self.assertEqual(detail['trigger_event'], event.pk)
        self.assertTrue(detail['rule_condition'] and detail['evidence'] and detail['occurred_at'])
        self.assertEqual(client.post('/api/alerts/', {}, format='json').status_code, 405)
        self.assertEqual(client.delete(f'/api/alerts/{alert.pk}/').status_code, 405)
        self.assertEqual(len(client.get(f'/api/events/{event.pk}/').json()), 11)
