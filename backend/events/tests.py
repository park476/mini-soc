from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError
from django.test import TestCase
from rest_framework.test import APIClient

from .models import LogSourceStatus, NormalizationFailure, SecurityEvent
from .test_nginx import SAMPLE_PATH
from .test_ssh import SSH_SAMPLE_PATH


class SecurityEventSliceTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_import_and_read_same_event(self):
        call_command('import_nginx_sample', str(SAMPLE_PATH), stdout=StringIO())
        event = SecurityEvent.objects.get()
        self.assertEqual(event.raw_log, SAMPLE_PATH.read_text(encoding='utf-8'))
        self.assertEqual(event.request_path, '/example')
        listing = self.client.get('/api/events/')
        detail = self.client.get(f'/api/events/{event.pk}/')
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(listing.json(), [detail.json()])
        self.assertEqual(detail.json()['raw_log'], event.raw_log)
        self.assertEqual(detail.json()['id'], event.pk)
        self.assertEqual(self.client.post('/api/events/', {}, format='json').status_code, 405)
        self.assertEqual(self.client.delete(f'/api/events/{event.pk}/').status_code, 405)

    def test_empty_and_missing(self):
        self.assertEqual(self.client.get('/api/events/').json(), [])
        self.assertEqual(self.client.get('/api/events/1/').status_code, 404)

    def test_invalid_sample_does_not_save(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'invalid.log'
            path.write_text('invalid log', encoding='utf-8')
            with self.assertRaisesMessage(CommandError, 'Sample was not saved'):
                call_command('import_nginx_sample', str(path))
        self.assertFalse(SecurityEvent.objects.exists())


class SshIngestTests(TestCase):
    def test_import_sample_saves_events_with_documented_fields(self):
        call_command('import_ssh_sample', str(SSH_SAMPLE_PATH), stdout=StringIO())
        events = SecurityEvent.objects.order_by('event_time')
        self.assertEqual([e.result for e in events], ['failure', 'failure', 'success'])
        self.assertTrue(all(e.source_type == 'ssh' and e.request_path == '' and e.http_status is None
                            for e in events))
        self.assertFalse(NormalizationFailure.objects.exists())
        detail = APIClient().get(f'/api/events/{events[0].pk}/').json()
        self.assertEqual(len(detail), 11)
        self.assertEqual(detail['ssh_evidence'], events[0].ssh_evidence)

    def test_unparsable_line_is_kept_as_failure(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'mixed.log'
            valid = SSH_SAMPLE_PATH.read_text(encoding='utf-8').splitlines(keepends=True)[0]
            path.write_text(valid + 'garbage line\n', encoding='utf-8')
            call_command('import_ssh_sample', str(path), stdout=StringIO())
        self.assertEqual(SecurityEvent.objects.count(), 1)
        failure = NormalizationFailure.objects.get()
        self.assertEqual(failure.source_type, 'ssh')
        self.assertEqual(failure.raw_log, 'garbage line\n')
        self.assertIn('Expected one supported sshd', failure.failure_reason)
        self.assertIsNotNone(failure.received_at)

    def test_unreadable_or_empty_file_saves_nothing(self):
        with TemporaryDirectory() as directory:
            empty = Path(directory) / 'empty.log'
            empty.write_text('\n', encoding='utf-8')
            for path in (empty, Path(directory) / 'missing.log'):
                with self.subTest(path=path), self.assertRaisesMessage(CommandError, 'Sample was not read'):
                    call_command('import_ssh_sample', str(path))
        self.assertFalse(SecurityEvent.objects.exists())
        self.assertFalse(NormalizationFailure.objects.exists())


class LogSourceStatusTests(TestCase):
    def test_defaults_and_one_row_per_source(self):
        status = LogSourceStatus.objects.create(source_type='ssh')
        self.assertIsNone(status.last_received_at)
        self.assertEqual(status.last_error, '')
        self.assertFalse(status.delivery_anomaly)
        with self.assertRaises(IntegrityError):
            LogSourceStatus.objects.create(source_type='ssh')
