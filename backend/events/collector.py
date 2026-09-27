"""TCP log collector on the monitoring server (T2-B, monitoring-server side only).

Wire format (controlled, NOT yet verified against a real victim rsyslog):

    <source_type>\\t<payload>\\n      source_type is 'nginx' or 'ssh'

Everything after the first TAB is the original log line and is stored verbatim as raw_log.
Framing is parsed by parse_frame() only, so it can be replaced once the real rsyslog template
output has been checked on the victim. Parsing/normalization reuses events.nginx / events.ssh.
The collector only stores SecurityEvent / NormalizationFailure and updates LogSourceStatus;
it does not run detection, correlation or response.
"""
import logging
import socketserver

from django.core.exceptions import ValidationError
from django.db import connections, transaction
from django.utils import timezone

from .models import LogSourceStatus, NormalizationFailure, SecurityEvent
from .nginx import normalize_nginx
from .ssh import normalize_ssh

logger = logging.getLogger('events.collector')

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 5514
MAX_LINE_BYTES = 16 * 1024
NORMALIZERS = {'nginx': normalize_nginx, 'ssh': normalize_ssh}


class FrameError(ValueError):
    """The line does not follow the transport framing; its source_type is unknown."""


def parse_frame(line):
    """Split one line (without its terminator) into (source_type, payload)."""
    source_type, sep, payload = line.partition('\t')
    if not sep:
        raise FrameError('Missing TAB separator between source_type and payload.')
    if source_type not in NORMALIZERS:
        raise FrameError(f'Unknown source_type {source_type[:32]!r}.')
    if not payload.strip():
        raise FrameError(f'Empty payload for source_type {source_type!r}.')
    return source_type, payload


def _mark_received(source_type, error=''):
    # delivery_anomaly (60s no-receive) is not evaluated here and keeps its stored value.
    status, _ = LogSourceStatus.objects.get_or_create(source_type=source_type)
    status.last_received_at = timezone.now()
    status.last_error = error
    status.save(update_fields=['last_received_at', 'last_error'])


def _store_failure(source_type, payload, reason):
    with transaction.atomic():
        NormalizationFailure.objects.create(source_type=source_type, raw_log=payload, failure_reason=reason)
        _mark_received(source_type, error=f'Normalization failed: {reason}')
    logger.warning('NormalizationFailure (%s): %s', source_type, reason)
    return 'failure'


def ingest_line(raw):
    """Store one received line (bytes, terminator removed). Returns 'event', 'failure' or 'rejected'."""
    try:
        source_type, payload = parse_frame(raw.decode('utf-8'))
    except UnicodeDecodeError:
        source, sep, payload_bytes = raw.partition(b'\t')
        if sep and source.decode('ascii', 'replace') in NORMALIZERS:
            # The source is known, so keep the undecodable payload as a failure record.
            return _store_failure(source.decode('ascii'), payload_bytes.decode('utf-8', 'backslashreplace'),
                                  'Payload is not valid UTF-8.')
        logger.error('Rejected line: not valid UTF-8 and no known source_type prefix.')
        return 'rejected'
    except FrameError as exc:
        logger.error('Rejected line: %s', exc)
        return 'rejected'
    try:
        event = SecurityEvent(**NORMALIZERS[source_type](payload))
        event.full_clean()
    except (ValueError, ValidationError) as exc:
        return _store_failure(source_type, payload, str(exc))
    with transaction.atomic():
        event.save()
        _mark_received(source_type)
    return 'event'


class LineHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = '%s:%s' % self.client_address[:2]
        logger.info('Connection from %s', peer)
        while True:
            chunk = self.rfile.readline(MAX_LINE_BYTES + 1)
            if not chunk:
                break
            if not chunk.endswith(b'\n'):
                if len(chunk) > MAX_LINE_BYTES:
                    self._discard_rest(peer)
                    continue
                logger.warning('Discarded partial line without newline at close from %s (%d bytes).', peer, len(chunk))
                break
            line = chunk[:-1].removesuffix(b'\r')
            if not line.strip():
                continue
            try:
                ingest_line(line)
            except Exception:  # one bad line or DB error must not stop the collector
                logger.exception('Failed to process a line from %s', peer)
        logger.info('Connection closed %s', peer)

    def _discard_rest(self, peer):
        while True:
            chunk = self.rfile.readline(MAX_LINE_BYTES + 1)
            if not chunk or chunk.endswith(b'\n'):
                break
        logger.error('Discarded oversized line (> %d bytes) from %s.', MAX_LINE_BYTES, peer)


class CollectorServer(socketserver.TCPServer):
    allow_reuse_address = True


class ThreadingCollectorServer(socketserver.ThreadingMixIn, CollectorServer):
    daemon_threads = True

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            connections.close_all()   # each connection thread has its own DB connection


def make_server(host=DEFAULT_HOST, port=DEFAULT_PORT, threaded=True):
    server_class = ThreadingCollectorServer if threaded else CollectorServer
    return server_class((host, port), LineHandler)
