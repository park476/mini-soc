from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest import TestCase as UnitTestCase

from django.core.management import call_command
from django.test import TestCase
from rest_framework.test import APIClient

from .correlation import compute_risk, run_correlation
from .models import Alert, CorrelationResult, Incident, RiskResult, SecurityEvent

BASE = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone(timedelta(hours=9)))
ATTACKER = '192.0.2.50'
OTHER = '198.51.100.9'


def alert(rule_type, seconds, ip=ATTACKER):
    at = BASE + timedelta(seconds=seconds)
    event = SecurityEvent.objects.create(
        source_type='ssh' if rule_type == 'ssh_brute_force' else 'nginx', event_time=at,
        source_ip=ip, action='controlled', result='controlled', raw_log='controlled',
    )
    created = Alert.objects.create(
        rule_type=rule_type, source_ip=ip, occurred_at=at, rule_condition='controlled',
        evidence='controlled', trigger_event=event,
    )
    created.related_events.set([event])
    return created


class RiskScoreTests(UnitTestCase):
    def test_scores_levels_and_cap(self):
        cases = [
            (['ssh_brute_force'], False, 40, 'Medium'),
            (['ssh_brute_force', 'nginx_suspicious_path'], False, 60, 'Medium'),
            (['ssh_brute_force', 'nginx_suspicious_path'], True, 90, 'High'),
            (['ssh_brute_force', 'nginx_scan'], True, 100, 'High'),
            (['ssh_brute_force', 'nginx_scan', 'nginx_suspicious_path'], True, 100, 'High'),
            (['nginx_suspicious_path'], False, 20, 'Low'),
            (['nginx_scan', 'nginx_suspicious_path'], False, 50, 'Medium'),
        ]
        for types, correlated, score, level in cases:
            with self.subTest(types=types, correlated=correlated):
                self.assertEqual(compute_risk(types, correlated)[:2], (score, level))
        _, _, _, basis = compute_risk(['ssh_brute_force', 'nginx_scan', 'nginx_suspicious_path'], True)
        self.assertEqual(basis['uncapped'], 120)
        self.assertEqual(basis['correlation_bonus'], 30)

    def test_repeated_rule_type_counts_once(self):
        self.assertEqual(compute_risk(['ssh_brute_force'] * 5, False)[:3], (40, 'Medium', ['ssh_brute_force']))


class CorrelationMatchTests(TestCase):
    def assert_single_incident(self, score):
        correlation = CorrelationResult.objects.get()
        self.assertTrue(correlation.matched)
        risk = RiskResult.objects.get()
        self.assertEqual((risk.score, risk.level, risk.correlation_applied), (score, 'High', True))
        incident = Incident.objects.get()
        self.assertEqual((incident.risk_score, incident.risk_level), (score, 'High'))
        self.assertEqual(incident.correlation, correlation)
        self.assertEqual(set(incident.alerts.all()), set(correlation.alerts.all()))
        return correlation, incident

    def test_ssh_and_scan_same_ip_within_10_minutes(self):
        ssh = alert('ssh_brute_force', 0)
        scan = alert('nginx_scan', 600)             # exactly 10 minutes: allowed
        self.assertEqual(run_correlation()['incidents'], 1)
        correlation, incident = self.assert_single_incident(100)
        self.assertEqual(set(correlation.alerts.all()), {ssh, scan})
        self.assertEqual((correlation.window_start, correlation.window_end), (ssh.occurred_at, scan.occurred_at))
        self.assertEqual(incident.occurred_at, scan.occurred_at)
        self.assertIn('600s apart', correlation.evidence)

    def test_ssh_and_suspicious_path_same_ip_within_10_minutes(self):
        alert('nginx_suspicious_path', 0)           # Nginx before SSH also counts
        alert('ssh_brute_force', 300)
        run_correlation()
        self.assert_single_incident(90)

    def test_all_three_types_capped_and_repeats_not_added(self):
        for s in (0, 30, 60):
            alert('ssh_brute_force', s)
        alert('nginx_scan', 120)
        alert('nginx_suspicious_path', 130)
        alert('nginx_suspicious_path', 140)
        run_correlation()
        correlation, _ = self.assert_single_incident(100)
        self.assertEqual(correlation.alerts.count(), 6)
        self.assertEqual(RiskResult.objects.get().score_basis['rule_scores'],
                         {'nginx_scan': 30, 'nginx_suspicious_path': 20, 'ssh_brute_force': 40})


class CorrelationNoMatchTests(TestCase):
    def assert_no_incident(self):
        self.assertFalse(CorrelationResult.objects.filter(matched=True).exists())
        self.assertFalse(Incident.objects.exists())
        self.assertFalse(RiskResult.objects.filter(correlation_applied=True).exists())

    def test_different_ip(self):
        alert('ssh_brute_force', 0)
        alert('nginx_scan', 60, ip=OTHER)
        run_correlation()
        self.assert_no_incident()
        self.assertEqual(sorted(RiskResult.objects.values_list('source_ip', 'score')),
                         [(ATTACKER, 40), (OTHER, 30)])

    def test_more_than_10_minutes_apart(self):
        alert('ssh_brute_force', 0)
        alert('nginx_suspicious_path', 601)
        run_correlation()
        self.assert_no_incident()
        self.assertEqual(sorted(RiskResult.objects.values_list('score', 'level')), [(20, 'Low'), (40, 'Medium')])

    def test_ssh_only(self):
        for s in (0, 60, 120, 180, 240):
            alert('ssh_brute_force', s)
        run_correlation()
        self.assert_no_incident()
        risk = RiskResult.objects.get()                 # 5 SSH alerts: 40, not 200
        self.assertEqual((risk.score, risk.level, risk.rule_types), (40, 'Medium', ['ssh_brute_force']))
        self.assertIn('No nginx_scan', CorrelationResult.objects.get().evidence)

    def test_nginx_only_even_if_score_is_medium(self):
        alert('nginx_scan', 0)
        alert('nginx_suspicious_path', 10)
        run_correlation()
        self.assert_no_incident()
        self.assertEqual((RiskResult.objects.get().score, RiskResult.objects.get().level), (50, 'Medium'))


class IdempotencyTests(TestCase):
    def test_rerun_does_not_duplicate(self):
        alert('ssh_brute_force', 0)
        alert('nginx_scan', 60)
        call_command('run_correlation', stdout=StringIO())
        counts = run_correlation()
        self.assertEqual((counts['created'], counts['updated'], counts['incidents']), (0, 0, 0))
        self.assertEqual((CorrelationResult.objects.count(), RiskResult.objects.count(),
                          Incident.objects.count()), (1, 1, 1))

    def test_new_alert_updates_same_judgment(self):
        alert('ssh_brute_force', 0)
        run_correlation()
        self.assertFalse(Incident.objects.exists())
        alert('nginx_suspicious_path', 60)
        counts = run_correlation()
        self.assertEqual((counts['created'], counts['updated'], counts['incidents']), (0, 1, 1))
        self.assertEqual(RiskResult.objects.get().score, 90)
        alert('nginx_scan', 90)
        run_correlation()
        self.assertEqual(Incident.objects.count(), 1)
        self.assertEqual(Incident.objects.get().risk_score, 90)   # snapshot at creation
        self.assertEqual(RiskResult.objects.get().score, 100)     # current judgment


class IncidentApiTests(TestCase):
    def test_read_only_list_and_detail(self):
        client = APIClient()
        self.assertEqual(client.get('/api/incidents/').json(), [])
        self.assertEqual(client.get('/api/incidents/1/').status_code, 404)
        ssh = alert('ssh_brute_force', 0)
        scan = alert('nginx_scan', 60)
        run_correlation()
        incident = Incident.objects.get()
        detail = client.get(f'/api/incidents/{incident.pk}/').json()
        self.assertEqual(client.get('/api/incidents/').json(), [detail])
        self.assertEqual(detail['source_ip'], ATTACKER)
        self.assertEqual(sorted(detail['alert_ids']), sorted([ssh.pk, scan.pk]))
        self.assertEqual({a['rule_type'] for a in detail['alerts']}, {'ssh_brute_force', 'nginx_scan'})
        self.assertEqual((detail['risk_score'], detail['risk_level']), (100, 'High'))
        self.assertTrue(detail['correlation']['matched'])
        self.assertIn('Same source_ip', detail['correlation']['evidence'])
        self.assertEqual(detail['correlation_result_id'], detail['correlation']['id'])
        self.assertTrue(detail['risk_result']['correlation_applied'])
        self.assertIn('>= 70', detail['creation_reason'])
        self.assertEqual(client.post('/api/incidents/', {}, format='json').status_code, 405)
        self.assertEqual(client.delete(f'/api/incidents/{incident.pk}/').status_code, 405)
