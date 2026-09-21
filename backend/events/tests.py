from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from rest_framework.test import APIClient

from .models import SecurityEvent
from .test_nginx import SAMPLE_PATH


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
