from datetime import timedelta
from pathlib import Path
from unittest import TestCase

from events.ssh import normalize_ssh


SSH_SAMPLE_PATH = Path(__file__).parent / 'samples' / 'ssh_auth.log'


class SshParsingTests(TestCase):
    def setUp(self):
        self.lines = SSH_SAMPLE_PATH.read_text(encoding='utf-8').splitlines(keepends=True)

    def test_failed_password_invalid_user(self):
        event = normalize_ssh(self.lines[0])
        self.assertEqual(event['source_type'], 'ssh')
        self.assertEqual(event['source_ip'], '192.0.2.20')
        self.assertEqual(event['action'], 'ssh_login')
        self.assertEqual(event['result'], 'failure')
        self.assertEqual(
            event['ssh_evidence'],
            'Failed password for invalid user admin from 192.0.2.20 port 51001 ssh2',
        )
        self.assertEqual(event['raw_log'], self.lines[0])
        self.assertEqual(event['event_time'].utcoffset(), timedelta(hours=9))
        self.assertNotIn('request_path', event)
        self.assertNotIn('http_status', event)

    def test_failed_valid_user_and_accepted_publickey(self):
        self.assertEqual(normalize_ssh(self.lines[1])['result'], 'failure')
        accepted = normalize_ssh(self.lines[2])
        self.assertEqual(accepted['result'], 'success')
        self.assertEqual(accepted['source_ip'], '198.51.100.5')

    def test_invalid_inputs_are_reported(self):
        raw = self.lines[0]
        for bad in (
            '', 'invalid log', raw + raw,
            raw.replace('192.0.2.20', '999.0.0.1'),
            raw.replace('2026-09-21T', '2026-13-21T'),
            raw.replace('+09:00', ''),
            raw.replace('sshd[2001]', 'cron[2001]'),
            raw.replace('Failed password', 'Disconnected from'),
            self.lines[2].replace('for demo', 'for invalid user demo'),
            'Sep 21 12:00:01 victim-sample sshd[2001]: Failed password for root from 192.0.2.20 port 1 ssh2',
        ):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                normalize_ssh(bad)

    def test_crlf_and_ipv6(self):
        raw = self.lines[1].rstrip('\n').replace('192.0.2.20', '2001:db8::20') + '\r\n'
        event = normalize_ssh(raw)
        self.assertEqual(event['source_ip'], '2001:db8::20')
        self.assertEqual(event['raw_log'], raw)
