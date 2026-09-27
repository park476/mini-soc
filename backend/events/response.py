"""Automatic SSH block for ssh_brute_force Alerts and its separate effect verification (T5).

Flow: ssh_brute_force Alert -> validate source_ip -> allowlist -> SSH to the victim ->
`sudo -n ufw prepend deny proto tcp from <ip> to any port 22` -> ResponseRecord.
Nothing is sent unless RESPONSE_EXECUTE is enabled and the victim settings are complete.
Tests inject a fake executor; no unblock is implemented (manual by an administrator).
"""
import ipaddress
import re
import shlex
import subprocess
from dataclasses import dataclass

from django.conf import settings
from django.utils import timezone

from .models import Alert, ResponseRecord, ResponseVerification

TRIGGER_RULE = 'ssh_brute_force'
BLOCKED_PORT = 22
SSH_TIMEOUT_SECONDS = 30
OUTPUT_LIMIT = 2000
RETRYABLE_STATUSES = ('failed',)
_HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.:-]*$')
_USER_RE = re.compile(r'^[a-z_][a-z0-9_-]*$')


# Starting state for a new or retried record: failed until a step proves otherwise.
RESET_FIELDS = {
    'target_ip': None, 'allowlist_result': 'unknown', 'allowlist_detail': '', 'execution_status': 'failed',
    'victim': '', 'command': '', 'execution_result': '', 'failure_reason': '',
    'executed_at': None, 'completed_at': None,
}


class ResponseConfigError(Exception):
    pass


def parse_allowlist(raw):
    """Comma-separated IPs or CIDR networks. An invalid entry is an error, never ignored."""
    networks = []
    for entry in (e.strip() for e in (raw or '').split(',')):
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise ResponseConfigError(f'Invalid RESPONSE_ALLOWLIST entry {entry!r}: {exc}') from exc
    return networks


def block_command(ip):
    return ['sudo', '-n', 'ufw', 'prepend', 'deny', 'proto', 'tcp', 'from', str(ip), 'to', 'any', 'port', str(BLOCKED_PORT)]


STATUS_COMMAND = ['sudo', '-n', 'ufw', 'status']


@dataclass(frozen=True)
class SshExecutor:
    """Runs a fixed remote argv on the victim over key-based SSH. Host keys must already be trusted."""
    host: str
    user: str
    port: int
    key_path: str = ''

    @classmethod
    def from_settings(cls):
        if not settings.RESPONSE_EXECUTE:
            raise ResponseConfigError('Remote execution is disabled (RESPONSE_EXECUTE is not true); no command was sent.')
        host, user = settings.RESPONSE_VICTIM_HOST.strip(), settings.RESPONSE_VICTIM_USER.strip()
        missing = [name for name, value in (('RESPONSE_VICTIM_HOST', host), ('RESPONSE_VICTIM_USER', user)) if not value]
        if missing:
            raise ResponseConfigError(f'Missing victim settings: {", ".join(missing)}; no command was sent.')
        if not _HOST_RE.match(host) or not _USER_RE.match(user):
            raise ResponseConfigError('Invalid RESPONSE_VICTIM_HOST or RESPONSE_VICTIM_USER; no command was sent.')
        try:
            port = int(settings.RESPONSE_VICTIM_SSH_PORT)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError as exc:
            raise ResponseConfigError('Invalid RESPONSE_VICTIM_SSH_PORT; no command was sent.') from exc
        return cls(host=host, user=user, port=port, key_path=settings.RESPONSE_SSH_KEY_PATH.strip())

    @property
    def label(self):
        return f'{self.user}@{self.host}:{self.port}'

    def run(self, remote_argv):
        argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-p', str(self.port)]
        if self.key_path:
            argv += ['-i', self.key_path, '-o', 'IdentitiesOnly=yes']
        # ssh passes the command to the remote shell as one string, so quote every argument.
        argv += ['--', f'{self.user}@{self.host}', shlex.join(remote_argv)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=SSH_TIMEOUT_SECONDS, check=False)


def _summary(result):
    parts = [f'exit={result.returncode}']
    for name, text in (('stdout', result.stdout), ('stderr', result.stderr)):
        if text and text.strip():
            parts.append(f'{name}: {text.strip()[:OUTPUT_LIMIT]}')
    return '\n'.join(parts)


def respond_to_alert(alert, executor=None, retry_failed=False):
    """Create (or, with retry_failed, redo a failed) ResponseRecord. Returns (record, executed_now)."""
    if alert.rule_type != TRIGGER_RULE:
        raise ValueError(f'Alert #{alert.pk} is {alert.rule_type}; only {TRIGGER_RULE} triggers a response.')
    record = ResponseRecord.objects.filter(triggering_alert=alert).first()
    if record and not (retry_failed and record.execution_status in RETRYABLE_STATUSES):
        return record, False
    record = record or ResponseRecord(triggering_alert=alert)
    for field, value in RESET_FIELDS.items():
        setattr(record, field, value)
    try:
        ip = ipaddress.ip_address(str(alert.source_ip))
    except ValueError:
        record.failure_reason = f'Invalid source_ip {alert.source_ip!r}; no command was sent.'
        record.save()
        return record, True
    record.target_ip = str(ip)
    record.command = shlex.join(block_command(ip))

    try:
        networks = parse_allowlist(settings.RESPONSE_ALLOWLIST)
    except ResponseConfigError as exc:
        record.allowlist_detail = str(exc)
        record.failure_reason = f'Allowlist could not be checked: {exc}'
        record.save()
        return record, True
    match = next((n for n in networks if ip.version == n.version and ip in n), None)
    if match:
        record.allowlist_result, record.execution_status = 'excluded', 'skipped'
        record.allowlist_detail = f'{ip} is in allowlist entry {match}'
        record.failure_reason = 'Allowlisted address: block command not executed.'
        record.save()
        return record, True
    record.allowlist_result = 'not_excluded'
    record.allowlist_detail = f'{ip} matched none of {len(networks)} allowlist entr{"y" if len(networks) == 1 else "ies"}'

    try:
        executor = executor or SshExecutor.from_settings()
    except ResponseConfigError as exc:
        record.failure_reason = f'Configuration error: {exc}'
        record.save()
        return record, True
    record.victim = executor.label
    record.executed_at = timezone.now()
    try:
        result = executor.run(block_command(ip))
    except subprocess.TimeoutExpired:
        record.execution_status = 'unknown'
        record.failure_reason = (f'SSH command timed out after {SSH_TIMEOUT_SECONDS}s; '
                                 'whether the rule was applied is unknown.')
    except OSError as exc:
        record.failure_reason = f'SSH could not be started: {exc}'
    else:
        record.execution_result = _summary(result)
        if result.returncode == 0:
            record.execution_status = 'succeeded'
        elif 'password is required' in (result.stderr or ''):
            record.failure_reason = 'Non-interactive sudo failed (sudo -n requires a password for ufw on the victim).'
        else:
            record.failure_reason = f'Remote command failed with exit code {result.returncode}.'
    record.completed_at = timezone.now()
    record.save()
    return record, True


def run_responses(alert_id=None, executor=None, retry_failed=False):
    """Process every ssh_brute_force Alert (or one) without a ResponseRecord. Returns processed records."""
    alerts = Alert.objects.filter(rule_type=TRIGGER_RULE).order_by('occurred_at', 'id')
    if alert_id is not None:
        alerts = alerts.filter(pk=alert_id)
    processed = []
    for alert in alerts:
        record, executed = respond_to_alert(alert, executor=executor, retry_failed=retry_failed)
        if executed:
            processed.append(record)
    return processed


_UFW_DENY_RE = re.compile(r'^(?P<to>\S+)(?: \(v6\))?\s+DENY(?: IN)?\s+(?P<source>\S+)')


def check_ufw_rule(executor, ip):
    """Read `ufw status` on the victim. Returns (ufw_rule_result, evidence)."""
    try:
        result = executor.run(STATUS_COMMAND)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 'unchecked', f'ufw status could not be read: {exc}'
    if result.returncode != 0:
        return 'unchecked', f'ufw status failed: {_summary(result)}'
    for line in result.stdout.splitlines():
        m = _UFW_DENY_RE.match(line.strip())
        if m and m['to'] == f'{BLOCKED_PORT}/tcp' and m['source'] == str(ip):
            return 'present', f'ufw status line: {line.strip()}'
    return 'absent', f'No "{BLOCKED_PORT}/tcp DENY {ip}" line in ufw status output.'


def record_verification(record, ufw_rule_result, ufw_evidence, reconnect_result, reconnect_evidence):
    if record.execution_status != 'succeeded':
        raise ValueError(f'ResponseRecord #{record.pk} is {record.execution_status}; only succeeded blocks are verified.')
    return ResponseVerification.objects.create(
        response=record, ufw_rule_result=ufw_rule_result, ufw_check_evidence=ufw_evidence,
        kali_ssh_reconnect_result=reconnect_result, reconnect_check_evidence=reconnect_evidence,
    )
