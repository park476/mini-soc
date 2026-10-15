"""IP-centred administrator actions for the React 관리자 패널: which IPs may be acted on, one read of
the victim's current UFW state, and a manual SSH (22/tcp) block, re-block or unblock.

A stored "succeeded" record is history only; the current state always comes from `ufw status`.
Which IPs (2026-10-15 decision): any source IP of a stored ssh_brute_force Alert, chosen by a superuser.
Nginx-only alerts are not SSH targets. Address rules are in address_policy (public, or a private lab
range in RESPONSE_SSH_PRIVATE_RANGES; never protected or special addresses or the requester).
Changes go through the victim's root-owned helper (deploy/victim/mini-soc-sshblock), which re-checks
everything; the read-only `sudo -n ufw status` is unchanged. The automatic response (response.py) and
the Django Admin unblock keep their direct UFW commands and policy.
"""
import ipaddress
import shlex

from django.conf import settings
from django.utils import timezone

from . import address_policy
from .models import Alert, ManualBlockRecord, ResponseRecord
from .response import BLOCKED_PORT, TRIGGER_RULE, ResponseConfigError, SshExecutor, _summary, find_deny_rule, STATUS_COMMAND
from .unblock import EXECUTE_SETTING as UNBLOCK_SETTING, _check, _run, unblock_response

BLOCK_SETTING = 'RESPONSE_MANUAL_BLOCK_EXECUTE'
PRIVATE_SETTING = 'RESPONSE_SSH_PRIVATE_RANGES'
SSH_HELPER = '/usr/local/sbin/mini-soc-sshblock'
# RFC 5737 / RFC 3849 documentation ranges used by fixtures and tests, plus loopback.
FIXTURE_NETWORKS = [ipaddress.ip_network(n) for n in (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32', '127.0.0.0/8', '::1/128',
)]


class ActionRefused(Exception):
    """Raised before anything is sent to the victim."""

    def __init__(self, kind, reason):
        super().__init__(reason)
        self.kind, self.reason = kind, reason


def is_fixture_ip(ip):
    ip = ipaddress.ip_address(str(ip))
    return any(ip.version == n.version and ip in n for n in FIXTURE_NETWORKS)


def helper_command(operation, ip):
    """The only change commands the panel sends: the helper runs the fixed UFW 22/tcp rule for this IP."""
    if operation not in ('block', 'unblock'):
        raise ValueError(f'Unknown SSH block operation {operation!r}.')
    return ['sudo', '-n', SSH_HELPER, operation, str(ipaddress.ip_address(str(ip)))]


def private_ranges():
    return address_policy.private_ranges(PRIVATE_SETTING)


def read_only_reason(raw_ip, operation='block', requester_ip=None):
    """'' when an administrator may run `operation` for this IP's SSH block; otherwise (kind, reason).
    Unblocking skips the address rules (a wrong block can always be released) and instead needs a
    succeeded block made by this system (see unblock_ip)."""
    try:
        ip = ipaddress.ip_address(str(raw_ip))
    except ValueError:
        return 'invalid_ip', f'Invalid IP {raw_ip!r}.'
    if is_fixture_ip(ip):
        return 'fixture', f'{ip} is a documentation/test address, not a real firewall target.'
    if getattr(settings, 'RESPONSE_OVERRIDES_ERROR', ''):
        return 'config', f'Response override file is invalid: {settings.RESPONSE_OVERRIDES_ERROR}'
    if operation == 'unblock':
        return ''
    refused = address_policy.address_refusal(ip, PRIVATE_SETTING, requester_ip, verb='SSH-blocked')
    if refused:
        return refused
    if not Alert.objects.filter(source_ip=str(ip), rule_type=TRIGGER_RULE).exists():
        return 'not_detected', f'{ip} has no {TRIGGER_RULE} Alert; only SSH attackers can be SSH-blocked.'
    return ''


def actionable_ip(raw_ip, operation='block', requester_ip=None):
    refused = read_only_reason(raw_ip, operation, requester_ip)
    if refused:
        raise ActionRefused(*refused)
    return ipaddress.ip_address(str(raw_ip))


def _executor(setting, executor=None):
    if getattr(settings, setting, False) is not True:
        raise ActionRefused('config', f'Disabled ({setting} is not true); no command was sent.')
    try:
        return executor or SshExecutor.from_settings(setting)
    except ResponseConfigError as exc:
        raise ActionRefused('config', f'Configuration error: {exc}') from exc


def read_ufw_states(ips, executor=None):
    """One read-only `ufw status` for all given IPs. Returns (states, failure_kind, detail);
    states maps ip -> 'present' | 'absent', and is empty when the state could not be read."""
    setting = next((s for s in (UNBLOCK_SETTING, BLOCK_SETTING) if getattr(settings, s, False) is True), UNBLOCK_SETTING)
    try:
        executor = _executor(setting, executor)
    except ActionRefused as exc:
        return {}, exc.kind, exc.reason
    result, kind, reason = _run(executor, STATUS_COMMAND)
    if kind:
        return {}, kind, reason
    return {str(ip): 'present' if find_deny_rule(result.stdout, ip) else 'absent' for ip in ips}, '', ''


def latest_block(ip):
    """Most recent succeeded block of this IP made by this system (automatic or manual), or None."""
    auto = ResponseRecord.objects.filter(target_ip=str(ip), action='block_ssh', execution_status='succeeded').order_by('-executed_at', '-id').first()
    manual = ManualBlockRecord.objects.filter(target_ip=str(ip), execution_status='succeeded').order_by('-executed_at', '-id').first()
    candidates = [r for r in (auto, manual) if r]
    return max(candidates, key=lambda r: r.executed_at) if candidates else None


def manual_block(raw_ip, requested_by, executor=None, requester_ip=None):
    """Block SSH from an IP with an ssh_brute_force Alert. Always returns a saved ManualBlockRecord.
    Earlier succeeded blocks do not stop this: only the current UFW state decides."""
    audit = ManualBlockRecord(requested_by=requested_by, requested_by_username=requested_by.get_username())

    def done(kind, reason):
        audit.failure_kind, audit.failure_reason = kind, reason
        audit.completed_at = timezone.now()
        audit.save()
        return audit

    try:
        try:
            audit.target_ip = str(ipaddress.ip_address(str(raw_ip)))
            audit.command = shlex.join(helper_command('block', raw_ip))
        except ValueError:
            pass
        ip = actionable_ip(raw_ip, 'block', requester_ip)
        executor = _executor(BLOCK_SETTING, executor)
    except ActionRefused as exc:
        return done(exc.kind, exc.reason)
    audit.victim = executor.label

    audit.ufw_before_result, audit.ufw_before_evidence, kind, reason = _check(executor, ip)
    if kind:
        return done(kind, f'UFW state could not be read before blocking; block was not sent. {reason}')
    if audit.ufw_before_result == 'present':
        audit.execution_status = 'skipped'
        audit.ufw_after_result, audit.ufw_after_evidence = 'present', 'Same check as before; no block was sent.'
        return done('', f'{ip} already has a {BLOCKED_PORT}/tcp DENY rule on the victim; a duplicate rule was not added.')

    audit.executed_at = timezone.now()
    result, kind, reason = _run(executor, helper_command('block', ip))
    if result is not None:
        audit.execution_result = _summary(result)
    if kind:
        if kind == 'timeout':
            audit.execution_status = 'unknown'
            reason += ' Whether the rule was added is unknown.'
        return done(kind, reason)
    audit.execution_status = 'succeeded'

    audit.ufw_after_result, audit.ufw_after_evidence, kind, reason = _check(executor, ip)
    if kind:
        return done(kind, f'Block command succeeded but UFW state could not be re-checked. {reason}')
    if audit.ufw_after_result == 'absent':
        return done('rule_not_present', 'Block command succeeded but no matching DENY rule is present; the IP is not blocked.')
    return done('', '')


def unblock_ip(raw_ip, requested_by, executor=None):
    """Unblock through the existing unblock service, sending the helper's unblock command. Returns an
    UnblockRecord, or raises ActionRefused when this system has no succeeded block for the IP, so
    UFW rules made by hand are never removed from the panel."""
    ip = actionable_ip(raw_ip, 'unblock')
    source = latest_block(ip)
    if source is None:
        raise ActionRefused('not_eligible', f'{ip} has no succeeded block made by this system; nothing to unblock.')
    return unblock_response(source, requested_by, executor=executor, command=lambda target: helper_command('unblock', target))
