"""Administrator-requested Nginx web block / unblock (port 8080 server block only) for the 관리자 패널.

Web requests reach the victim through Cloudflare Tunnel, so they arrive from cloudflared and UFW
cannot tell the attacker apart. Nginx already restores the client address (existing real-IP
settings, unchanged); a `deny <ip>;` list included only in the 8080 server block returns 403.

The victim side is one root-owned helper (deploy/victim/mini-soc-webblock) that sudoers allows only
with fixed arguments. Django sends `sudo -n <helper> status | block <ip> | unblock <ip>` and nothing
else. Flow mirrors the SSH block: refuse before sending -> status -> change only if needed -> status
again. Every attempt is a WebBlockRecord; the attacker's observed HTTP status is recorded separately.

Which IPs (2026-10-15 decision): any source IP of a stored Alert, chosen by a superuser in the panel.
No IP is typed in and no pre-registered target list exists. Blocking requires a normal public address
outside RESPONSE_ALLOWLIST; private addresses only inside RESPONSE_WEB_PRIVATE_RANGES (empty by default).
Loopback, link-local, reserved, multicast, unspecified and documentation addresses are never blocked,
nor the requesting administrator's own address. There is no automatic web block.
"""
import ipaddress
import re
import shlex

from django.conf import settings
from django.utils import timezone

from . import address_policy
from .ip_actions import ActionRefused, _executor, is_fixture_ip
from .models import Alert, WebBlockRecord
from .response import _summary
from .unblock import _run

HELPER = '/usr/local/sbin/mini-soc-webblock'
EXECUTE_SETTING = 'RESPONSE_WEB_BLOCK_EXECUTE'
PRIVATE_SETTING = 'RESPONSE_WEB_PRIVATE_RANGES'
WEB_PORT = 8080
STATUS_COMMAND = ['sudo', '-n', HELPER, 'status']
DONE_STATE = {'block': 'present', 'unblock': 'absent'}
EXPECTED_HTTP = {'block': 403, 'unblock': 200}
_DENY_RE = re.compile(r'^deny\s+(?P<ip>[0-9A-Fa-f:.]+);$')


def web_command(operation, ip):
    if operation not in DONE_STATE:
        raise ValueError(f'Unknown web block operation {operation!r}.')
    return ['sudo', '-n', HELPER, operation, str(ipaddress.ip_address(str(ip)))]


def private_ranges():
    return address_policy.private_ranges(PRIVATE_SETTING)


def refusal(raw_ip, operation='block', requester_ip=None):
    """'' when an administrator may run `operation` for this IP; otherwise (kind, reason).
    Unblocking skips the address-class and protection checks so a wrongly listed IP can always be released."""
    try:
        ip = ipaddress.ip_address(str(raw_ip))
    except ValueError:
        return 'invalid_ip', f'Invalid IP {raw_ip!r}.'
    if is_fixture_ip(ip):
        return 'fixture', f'{ip} is a documentation/test address, not a real web block target.'
    if getattr(settings, 'RESPONSE_OVERRIDES_ERROR', ''):
        return 'config', f'Response override file is invalid: {settings.RESPONSE_OVERRIDES_ERROR}'
    if operation == 'block':
        refused = address_policy.address_refusal(ip, PRIVATE_SETTING, requester_ip, verb='web-blocked')
        if refused:
            return refused
    if not Alert.objects.filter(source_ip=str(ip)).exists():
        return 'not_detected', f'{ip} has no Alert; only detected source IPs can be acted on.'
    return ''


def parse_status(output):
    """IPs listed as `deny <ip>;` in the helper's status output."""
    listed = set()
    for line in output.splitlines():
        m = _DENY_RE.match(line.strip())
        if m:
            try:
                listed.add(ipaddress.ip_address(m['ip']))
            except ValueError:
                continue
    return listed


def _check(executor, ip):
    """Read the Nginx 8080 blocklist. Returns (state, evidence, failure_kind, failure_reason)."""
    result, kind, reason = _run(executor, STATUS_COMMAND)
    if kind:
        return 'unchecked', f'{reason}\n{_summary(result)}' if result else reason, kind, reason
    if ip in parse_status(result.stdout):
        return 'present', f'Nginx {WEB_PORT} blocklist line: deny {ip};', '', ''
    return 'absent', f'No "deny {ip};" line in the Nginx {WEB_PORT} blocklist.', '', ''


def read_web_states(ips, executor=None):
    """One read-only helper `status` for all given IPs. Returns (states, failure_kind, detail);
    states maps ip -> 'present' | 'absent', and is empty when the state could not be read."""
    try:
        executor = _executor(EXECUTE_SETTING, executor)
    except ActionRefused as exc:
        return {}, exc.kind, exc.reason
    result, kind, reason = _run(executor, STATUS_COMMAND)
    if kind:
        return {}, kind, reason
    listed = parse_status(result.stdout)
    return {str(ip): 'present' if ipaddress.ip_address(str(ip)) in listed else 'absent' for ip in ips}, '', ''


def web_action(raw_ip, operation, requested_by=None, executor=None, requester_ip=None,
               execute_setting=EXECUTE_SETTING, origin='manual', trigger_alert=None, expires_at=None):
    """Block or unblock web access from one alerted IP. Always returns a saved WebBlockRecord.

    Manual admin actions pass a user (requested_by) and the default execute_setting. The PB-01 playbook
    passes requested_by=None, origin='auto', the triggering Alert and a TTL, and names its own switch so
    automatic blocking is enabled independently of manual web blocking."""
    want = DONE_STATE[operation]
    audit = WebBlockRecord(operation=operation, origin=origin, trigger_alert=trigger_alert, expires_at=expires_at,
                           requested_by=requested_by,
                           requested_by_username=requested_by.get_username() if requested_by else origin)

    def done(kind, reason):
        audit.failure_kind, audit.failure_reason = kind, reason
        audit.completed_at = timezone.now()
        audit.save()
        return audit

    refused = refusal(raw_ip, operation, requester_ip)
    if refused and refused[0] == 'invalid_ip':
        return done(*refused)
    ip = ipaddress.ip_address(str(raw_ip))
    audit.target_ip = str(ip)
    audit.command = shlex.join(web_command(operation, ip))
    if refused:
        return done(*refused)
    try:
        executor = _executor(execute_setting, executor)
    except ActionRefused as exc:
        return done(exc.kind, exc.reason)
    audit.victim = executor.label

    audit.state_before_result, audit.state_before_evidence, kind, reason = _check(executor, ip)
    if kind:
        return done(kind, f'Nginx blocklist could not be read before the {operation}; nothing was sent. {reason}')
    if audit.state_before_result == want:
        audit.execution_status = 'skipped'
        audit.state_after_result, audit.state_after_evidence = want, 'Same check as before; no change was sent.'
        return done('', f'{ip} is already {"web-blocked" if operation == "block" else "not web-blocked"}; nothing was sent.')

    audit.executed_at = timezone.now()
    result, kind, reason = _run(executor, web_command(operation, ip))
    if result is not None:
        audit.execution_result = _summary(result)
    if kind:
        if kind == 'timeout':
            audit.execution_status = 'unknown'
            reason += ' Whether the blocklist was changed is unknown.'
        return done(kind, reason)
    audit.execution_status = 'succeeded'

    audit.state_after_result, audit.state_after_evidence, kind, reason = _check(executor, ip)
    if kind:
        return done(kind, f'{operation} command succeeded but the blocklist could not be re-checked. {reason}')
    if audit.state_after_result != want:
        if operation == 'block':
            return done('rule_not_present', f'Block command succeeded but no "deny {ip};" line is listed; the IP is not blocked.')
        return done('rule_still_present', f'Unblock command succeeded but "deny {ip};" is still listed; the IP is still blocked.')
    return done('', '')


def record_http_check(record, http_status, evidence):
    """Store the HTTP status really observed from the attacker host after this record's change.
    Success means 403 after a block and 200 after an unblock; anything else is a failure."""
    if not record.target_ip or record.execution_status not in ('succeeded', 'skipped'):
        raise ValueError(f'WebBlockRecord #{record.pk} is {record.execution_status}; only a completed change can be verified.')
    if not 100 <= int(http_status) <= 599:
        raise ValueError(f'HTTP status must be between 100 and 599, got {http_status}.')
    record.http_check_status = int(http_status)
    record.http_check_result = 'success' if record.http_check_status == EXPECTED_HTTP[record.operation] else 'failed'
    record.http_check_evidence = evidence
    record.http_checked_at = timezone.now()
    record.save(update_fields=['http_check_status', 'http_check_result', 'http_check_evidence', 'http_checked_at'])
    return record
