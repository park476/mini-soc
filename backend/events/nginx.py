"""Parse one controlled Nginx combined-format access log, without database I/O."""

from datetime import datetime
from ipaddress import ip_address
import re


COMBINED_LOG = re.compile(
    r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/\d+\.\d+" '
    r'(?P<status>\d{3}) (?:\d+|-) '
    r'"(?:[^"\\\r\n]|\\.)*" "(?:[^"\\\r\n]|\\.)*"'
)


def normalize_nginx(raw_log):
    """Return documented SecurityEvent fields; reject unsupported/invalid input."""
    match = COMBINED_LOG.fullmatch(raw_log.removesuffix('\n').removesuffix('\r'))
    if not match:
        raise ValueError('Expected one Nginx combined-format access log line.')
    try:
        source_ip = str(ip_address(match['ip']))
        event_time = datetime.strptime(match['time'], '%d/%b/%Y:%H:%M:%S %z')
    except ValueError as exc:
        raise ValueError('Invalid source IP or timestamp in Nginx log.') from exc
    status = int(match['status'])
    if not 100 <= status <= 599:
        raise ValueError('HTTP status must be between 100 and 599.')
    if not match['target'].startswith('/'):
        raise ValueError('T1 supports request targets beginning with / only.')
    return {
        'source_type': 'nginx',
        'event_time': event_time,
        'source_ip': source_ip,
        'action': match['method'],
        'result': str(status),
        'request_path': match['target'].split('?', 1)[0],
        'http_status': status,
        'raw_log': raw_log,
    }
