"""Administrator-requested SSH unblock for one succeeded ResponseRecord.

Flow: RESPONSE_UNBLOCK_EXECUTE -> record is a succeeded block_ssh -> validate its stored target_ip ->
`sudo -n ufw status` -> only if the exact 22/tcp DENY rule exists:
`sudo -n ufw delete deny proto tcp from <ip> to any port 22` -> `sudo -n ufw status` again.
Every attempt is stored as an UnblockRecord; ResponseRecord and ResponseVerification are never written.
The IP comes only from the stored record, never from request input. RESPONSE_EXECUTE is not consulted.
"""
import ipaddress
import shlex
import subprocess

from django.conf import settings
from django.utils import timezone

from .models import ManualBlockRecord, UnblockRecord
from .response import (
    BLOCKED_PORT, SSH_TIMEOUT_SECONDS, STATUS_COMMAND, ResponseConfigError, SshExecutor, _summary, find_deny_rule,
)

EXECUTE_SETTING = 'RESPONSE_UNBLOCK_EXECUTE'
SSH_ERROR_EXIT = 255  # ssh's own exit code for connection/authentication failures


def unblock_command(ip):
    return ['sudo', '-n', 'ufw', 'delete', 'deny', 'proto', 'tcp', 'from', str(ip), 'to', 'any', 'port', str(BLOCKED_PORT)]


def _run(executor, argv):
    """Returns (result, failure_kind, failure_reason); result is None when no exit status was obtained."""
    try:
        result = executor.run(argv)
    except subprocess.TimeoutExpired:
        return None, 'timeout', f'SSH command timed out after {SSH_TIMEOUT_SECONDS}s: {shlex.join(argv)}'
    except OSError as exc:
        return None, 'ssh_error', f'SSH could not be started: {exc}'
    if result.returncode == 0:
        return result, '', ''
    stderr = result.stderr or ''
    if 'sudo:' in stderr or 'password is required' in stderr or 'not allowed to execute' in stderr:
        return result, 'sudo_denied', f'sudo refused the command on the victim: {shlex.join(argv)}'
    if result.returncode == SSH_ERROR_EXIT:
        return result, 'ssh_error', 'SSH connection or authentication to the victim failed.'
    return result, 'command_failed', f'Remote command failed with exit code {result.returncode}.'


def _check(executor, ip):
    """Read ufw status. Returns (ufw_result, evidence, failure_kind, failure_reason)."""
    result, kind, reason = _run(executor, STATUS_COMMAND)
    if kind:
        return 'unchecked', f'{reason}\n{_summary(result)}' if result else reason, kind, reason
    line = find_deny_rule(result.stdout, ip)
    if line:
        return 'present', f'ufw status line: {line}', '', ''
    return 'absent', f'No "{BLOCKED_PORT}/tcp DENY {ip}" line in ufw status output.', '', ''


class UnblockRefused(Exception):
    """Raised before anything is sent to the victim."""

    def __init__(self, kind, reason):
        super().__init__(reason)
        self.kind, self.reason = kind, reason


def _validated_ip(record):
    if getattr(record, 'action', 'block_ssh') != 'block_ssh' or record.execution_status != 'succeeded':
        raise UnblockRefused('not_eligible', f'{type(record).__name__} #{record.pk} is {record.execution_status}; '
                                             'only succeeded SSH blocks can be unblocked. No command was sent.')
    try:
        return ipaddress.ip_address(str(record.target_ip))
    except ValueError:
        raise UnblockRefused('invalid_ip', f'Invalid stored target_ip {record.target_ip!r}; no command was sent.') from None


def _enabled_executor(executor):
    # Checked here as well so an injected executor cannot bypass the opt-in.
    if getattr(settings, EXECUTE_SETTING, False) is not True:
        raise UnblockRefused('config', f'Unblock is disabled ({EXECUTE_SETTING} is not true); no command was sent.')
    try:
        return executor or SshExecutor.from_settings(EXECUTE_SETTING)
    except ResponseConfigError as exc:
        raise UnblockRefused('config', f'Configuration error: {exc}') from exc


def check_block_state(record, executor=None):
    """Read-only `ufw status` for the record's stored IP; changes nothing and stores nothing.
    Returns (ufw_result, evidence, failure_kind). A past succeeded block says nothing about this."""
    try:
        ip = _validated_ip(record)
        executor = _enabled_executor(executor)
    except UnblockRefused as exc:
        return 'unchecked', exc.reason, exc.kind
    result, evidence, kind, _ = _check(executor, ip)
    return result, evidence, kind


def unblock_response(record, requested_by, executor=None, command=unblock_command):
    """Remove the SSH block created by `record` (a succeeded ResponseRecord or ManualBlockRecord).
    Always returns a saved UnblockRecord. Earlier UnblockRecords never prevent a new attempt.
    `command` builds the remote argv; the admin panel passes the victim helper's, Django Admin the default."""
    source = {'manual_block': record} if isinstance(record, ManualBlockRecord) else {'response': record}
    audit = UnblockRecord(requested_by=requested_by, requested_by_username=requested_by.get_username(), **source)

    def fail(kind, reason):
        audit.failure_kind, audit.failure_reason = kind, reason
        audit.completed_at = timezone.now()
        audit.save()
        return audit

    try:
        ip = _validated_ip(record)
        audit.target_ip = str(ip)
        audit.command = shlex.join(command(ip))
        executor = _enabled_executor(executor)
    except UnblockRefused as exc:
        return fail(exc.kind, exc.reason)
    audit.victim = executor.label

    audit.ufw_before_result, audit.ufw_before_evidence, kind, reason = _check(executor, ip)
    if kind:
        return fail(kind, f'UFW state could not be read before unblocking; delete was not sent. {reason}')
    if audit.ufw_before_result == 'absent':
        audit.execution_status = 'skipped'
        audit.ufw_after_result, audit.ufw_after_evidence = 'absent', 'Same check as before; no delete was sent.'
        return fail('', f'{ip} has no 22/tcp DENY rule on the victim (already unblocked); delete was not sent.')

    audit.executed_at = timezone.now()
    result, kind, reason = _run(executor, command(ip))
    if result is not None:
        audit.execution_result = _summary(result)
    if kind:
        if kind == 'timeout':
            audit.execution_status = 'unknown'
            reason += ' Whether the rule was deleted is unknown.'
        return fail(kind, reason)
    audit.execution_status = 'succeeded'

    audit.ufw_after_result, audit.ufw_after_evidence, kind, reason = _check(executor, ip)
    if kind:
        return fail(kind, f'Delete command succeeded but UFW state could not be re-checked. {reason}')
    if audit.ufw_after_result == 'present':
        return fail('rule_still_present', 'Delete command succeeded but a matching DENY rule is still present '
                                          '(possibly a duplicate rule); the IP is still blocked.')
    return fail('', '')
