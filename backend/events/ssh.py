"""Parse one controlled sshd authentication log line, without database I/O."""

from datetime import datetime
from ipaddress import ip_address
import re


# rsyslog high-precision (RFC 3339) prefix; the offset is required so no year/zone is guessed.
SSHD_AUTH_LOG = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})) '
    r'\S+ sshd(?:-session)?(?:\[\d+\])?: '
    r'(?P<message>(?P<outcome>Failed|Accepted) (?:password|publickey) for '
    r'(?P<invalid>invalid user )?\S+ from (?P<ip>\S+) port \d+ ssh2(?:: [^\r\n]+)?)'
)


def normalize_ssh(raw_log):
    """Return documented SecurityEvent fields; reject unsupported/invalid input."""
    match = SSHD_AUTH_LOG.fullmatch(raw_log.removesuffix('\n').removesuffix('\r'))
    if not match:
        raise ValueError('Expected one supported sshd Failed/Accepted authentication line.')
    if match['outcome'] == 'Accepted' and match['invalid']:
        raise ValueError('Accepted authentication cannot be for an invalid user.')
    try:
        source_ip = str(ip_address(match['ip']))
        event_time = datetime.fromisoformat(match['time'])
    except ValueError as exc:
        raise ValueError('Invalid source IP or timestamp in sshd log.') from exc
    return {
        'source_type': 'ssh',
        'event_time': event_time,
        'source_ip': source_ip,
        'action': 'ssh_login',
        'result': 'failure' if match['outcome'] == 'Failed' else 'success',
        'ssh_evidence': match['message'],
        'raw_log': raw_log,
    }
