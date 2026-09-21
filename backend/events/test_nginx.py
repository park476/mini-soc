from datetime import timedelta
from pathlib import Path
from unittest import TestCase

from events.nginx import normalize_nginx


SAMPLE_PATH = Path(__file__).parent / 'samples' / 'nginx_access.log'


class NginxParsingTests(TestCase):
    def setUp(self):
        self.raw = SAMPLE_PATH.read_text(encoding='utf-8')

    def test_sample_preserves_evidence_and_normalizes_fields(self):
        event = normalize_nginx(self.raw)
        self.assertEqual(event['raw_log'], self.raw)
        self.assertEqual(event['request_path'], '/example')
        self.assertEqual(event['source_ip'], '192.0.2.10')
        self.assertEqual(event['action'], 'GET')
        self.assertEqual(event['http_status'], 200)
        self.assertEqual(event['result'], '200')
        self.assertEqual(event['event_time'].utcoffset(), timedelta(hours=9))

    def test_invalid_inputs_are_reported(self):
        for raw in (
            '', 'invalid log', self.raw + self.raw,
            self.raw.replace('192.0.2.10', '999.0.0.1'),
            self.raw.replace('21/Sep', '32/Sep'),
            self.raw.replace(' 200 ', ' 999 '),
            self.raw.replace('/example?demo=1', '*'),
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalize_nginx(raw)

    def test_crlf_and_ipv6(self):
        raw = self.raw.rstrip('\n').replace('192.0.2.10', '2001:db8::1') + '\r\n'
        event = normalize_nginx(raw)
        self.assertEqual(event['source_ip'], '2001:db8::1')
        self.assertEqual(event['raw_log'], raw)
