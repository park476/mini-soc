import socket
import threading
from io import StringIO
from pathlib import Path
from unittest import TestCase as UnitTestCase

from django.core.management import call_command
from django.test import TestCase

from .collector import MAX_LINE_BYTES, FrameError, ingest_line, make_server, parse_frame
from .models import LogSourceStatus, NormalizationFailure, SecurityEvent
from .test_nginx import SAMPLE_PATH
from .test_ssh import SSH_SAMPLE_PATH

CONTROLLED_PATH = Path(__file__).parent / 'samples' / 'collector_controlled.log'
NGINX = '192.0.2.10 - - [21/Sep/2026:12:00:00 +0900] "GET /example?q=1 HTTP/1.1" 404 123 "-" "controlled-tcp"'
SSH = ('2026-09-21T12:00:01+09:00 victim-sample sshd[100]: '
       'Failed password for invalid user admin from 192.0.2.20 port 55555 ssh2')
BAD_NGINX = 'this is not an nginx combined log line'


def frame(source, payload):
    return f'{source}\t{payload}'.encode()


class FramingTests(UnitTestCase):
    def test_valid_frames(self):
        self.assertEqual(parse_frame(f'nginx\t{NGINX}'), ('nginx', NGINX))
        self.assertEqual(parse_frame(f'ssh\t{SSH}'), ('ssh', SSH))
        self.assertEqual(parse_frame('nginx\ta\tb'), ('nginx', 'a\tb'))   # only the first TAB splits

    def test_invalid_frames(self):
        for line in ('apache\tGET /', f'NGINX\t{NGINX}', NGINX, 'nginx\t', 'ssh\t   ', '\tpayload'):
            with self.subTest(line=line), self.assertRaises(FrameError):
                parse_frame(line)


class IngestTests(TestCase):
    def status(self, source):
        return LogSourceStatus.objects.get(source_type=source)

    def test_nginx_and_ssh_payloads_become_events_with_raw_preserved(self):
        self.assertEqual(ingest_line(frame('nginx', NGINX)), 'event')
        self.assertEqual(ingest_line(frame('ssh', SSH)), 'event')
        nginx = SecurityEvent.objects.get(source_type='nginx')
        ssh = SecurityEvent.objects.get(source_type='ssh')
        self.assertEqual((nginx.raw_log, nginx.request_path, nginx.http_status), (NGINX, '/example', 404))
        self.assertEqual((ssh.raw_log, ssh.result, ssh.source_ip), (SSH, 'failure', '192.0.2.20'))
        for source in ('nginx', 'ssh'):
            self.assertIsNotNone(self.status(source).last_received_at)
            self.assertEqual(self.status(source).last_error, '')
            self.assertFalse(self.status(source).delivery_anomaly)

    def test_parser_failure_is_kept_and_cleared_by_next_good_line(self):
        with self.assertLogs('events.collector', 'WARNING'):
            self.assertEqual(ingest_line(frame('nginx', BAD_NGINX)), 'failure')
        self.assertFalse(SecurityEvent.objects.exists())
        failure = NormalizationFailure.objects.get()
        self.assertEqual((failure.source_type, failure.raw_log), ('nginx', BAD_NGINX))
        self.assertIn('Nginx combined-format', failure.failure_reason)
        first = self.status('nginx')
        self.assertIsNotNone(first.last_received_at)
        self.assertIn('Normalization failed', first.last_error)
        self.assertEqual(ingest_line(frame('nginx', NGINX)), 'event')
        second = self.status('nginx')
        self.assertEqual(second.last_error, '')
        self.assertGreaterEqual(second.last_received_at, first.last_received_at)
        self.assertFalse(LogSourceStatus.objects.filter(source_type='ssh').exists())

    def test_traditional_syslog_timestamp_is_not_guessed(self):
        traditional = SSH.replace('2026-09-21T12:00:01+09:00', 'Sep 21 12:00:01')
        with self.assertLogs('events.collector', 'WARNING'):
            self.assertEqual(ingest_line(frame('ssh', traditional)), 'failure')
        self.assertFalse(SecurityEvent.objects.exists())

    def test_rejected_frames_store_nothing(self):
        for raw in (b'apache\tGET /', NGINX.encode(), b'\xff\xfe\tbad'):
            with self.subTest(raw=raw), self.assertLogs('events.collector', 'ERROR'):
                self.assertEqual(ingest_line(raw), 'rejected')
        self.assertFalse(SecurityEvent.objects.exists() or NormalizationFailure.objects.exists()
                         or LogSourceStatus.objects.exists())

    def test_invalid_utf8_with_known_source_is_a_failure(self):
        with self.assertLogs('events.collector', 'WARNING'):
            self.assertEqual(ingest_line(b'ssh\tFailed \xff'), 'failure')
        self.assertIn('UTF-8', NormalizationFailure.objects.get().failure_reason)

    def test_sample_importers_do_not_touch_source_status(self):
        call_command('import_nginx_sample', str(SAMPLE_PATH), stdout=StringIO())
        call_command('import_ssh_sample', str(SSH_SAMPLE_PATH), stdout=StringIO())
        self.assertTrue(SecurityEvent.objects.exists())
        self.assertFalse(LogSourceStatus.objects.exists())


class SocketCollectorTests(TestCase):
    """Real TCP through a localhost ephemeral port; the server handles in this thread's DB connection."""

    def send(self, data):
        server = make_server('127.0.0.1', 0, threaded=False)
        port = server.server_address[1]

        def client():
            with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
                conn.sendall(data)

        sender = threading.Thread(target=client)
        sender.start()
        try:
            server.timeout = 5
            server.handle_request()
        finally:
            sender.join()
            server.server_close()

    def test_controlled_file_over_tcp(self):
        with self.assertLogs('events.collector', 'INFO'):
            self.send(CONTROLLED_PATH.read_bytes())
        self.assertEqual(sorted(SecurityEvent.objects.values_list('source_type', flat=True)), ['nginx', 'ssh'])
        self.assertEqual(NormalizationFailure.objects.get().raw_log, BAD_NGINX)
        self.assertIn('Normalization failed', LogSourceStatus.objects.get(source_type='nginx').last_error)
        self.assertEqual(LogSourceStatus.objects.get(source_type='ssh').last_error, '')
        self.assertTrue(all(s.last_received_at for s in LogSourceStatus.objects.all()))

    def test_bad_oversized_blank_crlf_and_partial_lines(self):
        data = b''.join([
            b'garbage without tab\n',
            b'\n   \n',
            b'nginx\t' + b'A' * (MAX_LINE_BYTES * 2) + b'\n',
            frame('ssh', SSH) + b'\r\n',
            frame('nginx', NGINX),                      # no trailing newline: discarded at close
        ])
        with self.assertLogs('events.collector', 'INFO') as logs:
            self.send(data)
        event = SecurityEvent.objects.get()
        self.assertEqual((event.source_type, event.raw_log), ('ssh', SSH))
        self.assertFalse(NormalizationFailure.objects.exists())
        output = '\n'.join(logs.output)
        self.assertIn('Rejected line', output)
        self.assertIn('Discarded oversized line', output)
        self.assertIn('Discarded partial line', output)
