from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .correlation import run_correlation
from .models import LogSourceStatus, NormalizationFailure
from .test_correlation import OTHER, alert

TOP_KEYS = {'source_status', 'counts', 'recent_events', 'recent_alerts', 'recent_incidents', 'recent_responses'}
COUNT_KEYS = {'events', 'nginx_events', 'ssh_events', 'alerts', 'incidents', 'high_incidents', 'responses'}
STATUS_KEYS = {'source_type', 'recorded', 'last_received_at', 'last_error', 'delivery_anomaly'}


class DashboardApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def get(self):
        response = self.client.get('/api/dashboard/')
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_empty_database_is_safe(self):
        data = self.get()
        self.assertEqual(set(data), TOP_KEYS)
        self.assertEqual(data['counts'], dict.fromkeys(COUNT_KEYS, 0))
        self.assertEqual([s['source_type'] for s in data['source_status']], ['nginx', 'ssh'])
        for status in data['source_status']:
            self.assertEqual(set(status), STATUS_KEYS)
            self.assertEqual((status['recorded'], status['last_received_at'], status['last_error'],
                              status['delivery_anomaly']), (False, None, '', False))
        self.assertFalse(LogSourceStatus.objects.exists())     # reading never creates status rows
        for key in TOP_KEYS - {'source_status', 'counts'}:
            self.assertEqual(data[key], [])

    def test_counts_and_recent_records(self):
        for s in (0, 60):
            alert('ssh_brute_force', s)                         # one ssh event per alert
        alert('nginx_scan', 90)                                 # nginx event
        alert('nginx_suspicious_path', 0, ip=OTHER)             # nginx event, other IP (no incident)
        run_correlation()
        NormalizationFailure.objects.create(source_type='nginx', raw_log='bad', failure_reason='x')
        data = self.get()
        self.assertEqual(data['counts'], {
            'events': 4, 'nginx_events': 2, 'ssh_events': 2, 'alerts': 4,
            'incidents': 1, 'high_incidents': 1, 'responses': 0,
        })
        self.assertEqual(len(data['recent_events']), 4)
        self.assertEqual(data['recent_incidents'][0]['risk_level'], 'High')
        self.assertEqual(data['recent_alerts'][0]['rule_type'], 'nginx_scan')   # newest first
        self.assertEqual(len(data['recent_events'][0]), 11)                     # same event contract

    def test_recorded_status_values(self):
        received = timezone.now()
        LogSourceStatus.objects.create(source_type='ssh', last_received_at=received,
                                       last_error='Normalization failed: x', delivery_anomaly=True)
        nginx, ssh = self.get()['source_status']
        self.assertFalse(nginx['recorded'])
        self.assertTrue(ssh['recorded'])
        self.assertEqual(ssh['last_error'], 'Normalization failed: x')
        self.assertTrue(ssh['delivery_anomaly'])
        self.assertEqual(ssh['last_received_at'], received.isoformat().replace('+00:00', 'Z'))

    def test_read_only(self):
        for method in ('post', 'put', 'patch', 'delete'):
            with self.subTest(method=method):
                self.assertEqual(getattr(self.client, method)('/api/dashboard/', {}, format='json').status_code, 405)
