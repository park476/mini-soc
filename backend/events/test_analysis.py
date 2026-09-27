from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from .analysis import run_cycle
from .correlation import run_correlation
from .models import Alert, CorrelationResult, Incident, ResponseRecord, RiskResult
from .test_detection import ATTACKER, nginx, ssh
from .test_response import SAFE_SETTINGS, FakeExecutor, no_real_subprocess


def controlled_attack():
    """5 SSH failures, then 10 distinct 404 paths including /admin, all from ATTACKER."""
    for s in (0, 10, 20, 30, 40):
        ssh(s)
    nginx(60, '/admin')
    for i in range(9):
        nginx(65 + i * 5, f'/probe{i}')


def once():
    out = StringIO()
    call_command('run_analysis', '--once', stdout=out)
    return out.getvalue()


@override_settings(**SAFE_SETTINGS)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class RunAnalysisTests(TestCase):
    def test_once_runs_full_flow_without_response_when_disabled(self):
        controlled_attack()
        output = once()
        self.assertEqual(sorted(Alert.objects.values_list('rule_type', flat=True)),
                         ['nginx_scan', 'nginx_suspicious_path', 'ssh_brute_force'])
        correlation = CorrelationResult.objects.get()
        self.assertTrue(correlation.matched)
        self.assertEqual((RiskResult.objects.get().score, RiskResult.objects.get().level), (100, 'High'))
        incident = Incident.objects.get()
        self.assertEqual((incident.source_ip, incident.risk_score), (ATTACKER, 100))
        self.assertFalse(ResponseRecord.objects.exists())
        self.assertIn('alerts created 3', output)
        self.assertIn('response disabled', output)
        self.assertIn('incidents created 1', output)

    def test_second_once_is_idempotent(self):
        controlled_attack()
        once()
        output = once()
        self.assertEqual((Alert.objects.count(), CorrelationResult.objects.count(),
                          RiskResult.objects.count(), Incident.objects.count(), ResponseRecord.objects.count()),
                         (3, 1, 1, 1, 0))
        self.assertIn('alerts created 0', output)
        self.assertIn('correlations created 0/updated 0/unchanged 1/removed 0; incidents created 0', output)

    def test_response_path_when_enabled_uses_injected_executor(self):
        controlled_attack()
        fake = FakeExecutor()
        with self.settings(RESPONSE_EXECUTE=True):
            first = run_cycle(executor=fake)
            second = run_cycle(executor=fake)
        self.assertEqual(first['response'], {'enabled': True, 'processed': 1, 'statuses': {'succeeded': 1}})
        self.assertEqual(second['response'], {'enabled': True, 'processed': 0, 'statuses': {}})
        record = ResponseRecord.objects.get()
        self.assertEqual((record.triggering_alert.rule_type, record.target_ip), ('ssh_brute_force', ATTACKER))
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(Incident.objects.count(), 1)

    def test_interval_below_one_second_is_rejected(self):
        for value in ('0.5', '0', '-1', 'nan'):
            with self.subTest(value=value), self.assertRaisesMessage(CommandError, 'at least 1'):
                call_command('run_analysis', '--interval', value)

    def test_step_error_is_reported_and_later_steps_still_run(self):
        controlled_attack()
        with mock.patch('events.analysis.run_detection', side_effect=RuntimeError('boom')), \
                self.assertLogs('events.analysis', 'ERROR') as logs:
            summary = run_cycle()
            with self.assertRaisesMessage(CommandError, 'detection: boom'):
                once()
        self.assertEqual(summary['errors'], ['detection: boom'])
        self.assertIsNotNone(summary['correlation'])
        self.assertIn('Analysis step detection failed', logs.output[0])

    def test_continuous_loop_survives_errors_and_stops_on_ctrl_c(self):
        controlled_attack()
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 2:
                raise KeyboardInterrupt

        calls = []

        def flaky_correlation():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('db down')
            return run_correlation()

        out = StringIO()
        # close_old_connections would close the TestCase transaction's connection; it is only a reconnect aid.
        with mock.patch('events.analysis.run_correlation', flaky_correlation), \
                mock.patch('events.management.commands.run_analysis.close_old_connections'), \
                mock.patch('events.management.commands.run_analysis.time.sleep', fake_sleep), \
                self.assertLogs('events.analysis', 'ERROR'):
            call_command('run_analysis', '--interval', '2', stdout=out)
        self.assertEqual(sleeps, [2.0, 2.0])
        output = out.getvalue()
        self.assertIn('correlation failed', output)
        self.assertIn('incidents created 1', output)       # second cycle retried and succeeded
        self.assertIn('Analysis loop stopped', output)
        self.assertEqual(Incident.objects.count(), 1)
