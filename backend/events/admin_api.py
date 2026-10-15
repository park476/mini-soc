"""Session-authenticated JSON API behind the React 관리자 패널.

Plain Django views (not DRF) so CsrfViewMiddleware protects every POST, including login.
Every data view re-checks is_active and is_superuser on the server; the React UI is not trusted.
Unblocking only passes a ResponseRecord id to events/unblock.py; no IP or command is accepted.
IP actions (SSH and Nginx web) accept only an IP, re-validated server-side; never a command.
"""
import json
from functools import wraps

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from django.db.models import Count, Max

from .ip_actions import (
    BLOCK_SETTING, ActionRefused, approved_targets, is_fixture_ip, latest_block, manual_block, read_only_reason,
    read_ufw_states, unblock_ip,
)
from .models import Alert, Incident, ManualBlockRecord, ResponseRecord, RiskResult, UnblockRecord, WebBlockRecord
from .response import BLOCKED_PORT, ResponseConfigError
from .unblock import EXECUTE_SETTING, check_block_state, unblock_response
from . import web_block

HISTORY_LIMIT = 100
# HTTP status for an unblock attempt that did not end as succeeded/skipped.
FAILURE_STATUS = {'not_eligible': 409, 'invalid_ip': 409, 'config': 503, 'fixture': 403, 'not_approved': 403,
                  'not_detected': 403, 'allowlisted': 403, 'not_public': 403, 'self': 403}


def is_panel_admin(user):
    return user.is_authenticated and user.is_active and user.is_superuser


def superuser_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': '관리자 로그인이 필요합니다.'}, status=401)
        if not is_panel_admin(request.user):
            return JsonResponse({'detail': '관리자(superuser) 권한이 없습니다.'}, status=403)
        return view(request, *args, **kwargs)
    return never_cache(wrapped)


def _session(user):
    admin = is_panel_admin(user)
    return {'authenticated': admin, 'username': user.get_username() if admin else ''}


def _unblock(u):
    return {
        'id': u.pk, 'response_id': u.response_id, 'target_ip': u.target_ip,
        'requested_by': u.requested_by_username, 'requested_at': u.requested_at,
        'execution_status': u.execution_status, 'failure_kind': u.failure_kind, 'failure_reason': u.failure_reason,
        'command': u.command, 'execution_result': u.execution_result,
        'ufw_before_result': u.ufw_before_result, 'ufw_after_result': u.ufw_after_result,
        'ufw_after_evidence': u.ufw_after_evidence,
        'kali_ssh_reconnect_result': u.kali_ssh_reconnect_result, 'completed_at': u.completed_at,
    }


def _block(r):
    verifications = sorted(r.verifications.all(), key=lambda v: (v.verified_at, v.pk))
    return {
        'id': r.pk, 'target_ip': r.target_ip, 'triggering_alert_id': r.triggering_alert_id,
        'rule_type': r.triggering_alert.rule_type,
        # Past result of the block command only; the current UFW state comes from the check endpoint.
        'execution_status': r.execution_status, 'executed_at': r.executed_at, 'command': r.command,
        'victim': r.victim, 'verification_status': verifications[-1].verification_status if verifications else None,
        'eligible': r.action == 'block_ssh' and r.execution_status == 'succeeded',
        'unblocks': [_unblock(u) for u in sorted(r.unblocks.all(), key=lambda u: -u.pk)],
    }


@never_cache
@ensure_csrf_cookie
@require_GET
def session_view(request):
    return JsonResponse(_session(request.user))


@never_cache
@csrf_protect
@require_POST
def login_view(request):
    try:
        body = json.loads(request.body or b'{}')
        username, password = body['username'], body['password']
        if not isinstance(username, str) or not isinstance(password, str):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        return JsonResponse({'detail': '아이디와 비밀번호를 입력하세요.'}, status=400)
    user = authenticate(request, username=username, password=password)  # rejects inactive users
    if user is None:
        return JsonResponse({'detail': '아이디 또는 비밀번호가 올바르지 않습니다.'}, status=401)
    if not is_panel_admin(user):
        return JsonResponse({'detail': '관리자(superuser) 권한이 없습니다.'}, status=403)
    login(request, user)
    return JsonResponse(_session(user))


@never_cache
@csrf_protect
@require_POST
def logout_view(request):
    logout(request)
    return JsonResponse({'authenticated': False, 'username': ''})


@superuser_required
@require_GET
def blocks_view(request):
    records = (ResponseRecord.objects.filter(action='block_ssh').select_related('triggering_alert')
               .prefetch_related('verifications', 'unblocks').order_by('-id'))
    return JsonResponse({
        'unblock_enabled': getattr(settings, EXECUTE_SETTING, False) is True,
        'execute_setting': EXECUTE_SETTING,
        'blocks': [_block(r) for r in records],
    })


@superuser_required
@csrf_protect
@require_POST
def check_view(request, pk):
    record = get_object_or_404(ResponseRecord, pk=pk)
    ufw_state, evidence, failure_kind = check_block_state(record)
    return JsonResponse({'response_id': record.pk, 'target_ip': record.target_ip, 'ufw_state': ufw_state,
                         'evidence': evidence, 'failure_kind': failure_kind, 'checked_at': timezone.now()})


@superuser_required
@csrf_protect
@require_POST
def unblock_view(request, pk):
    record = get_object_or_404(ResponseRecord, pk=pk)
    try:
        confirmed = json.loads(request.body or b'{}').get('confirm') is True
    except (ValueError, AttributeError):
        confirmed = False
    if not confirmed:
        return JsonResponse({'detail': '명시적 확인(confirm)이 필요합니다. 명령을 보내지 않았습니다.'}, status=400)
    audit = unblock_response(record, request.user)
    if audit.execution_status == 'skipped':
        outcome, status = 'already_unblocked', 200
    elif audit.execution_status == 'succeeded' and audit.ufw_after_result == 'absent':
        outcome, status = 'unblocked', 200
    else:
        outcome, status = 'failed', FAILURE_STATUS.get(audit.failure_kind, 502)
    return JsonResponse({'outcome': outcome, 'detail': audit.failure_reason, 'unblock': _unblock(audit)}, status=status)


@superuser_required
@require_GET
def unblocks_view(request):
    return JsonResponse({'unblocks': [_unblock(u) for u in UnblockRecord.objects.order_by('-id')[:HISTORY_LIMIT]]})


# ---- IP-centred threat management -------------------------------------------------------------

def _action(kind, r):
    """One row of block/unblock history. kind: auto_block | manual_block | unblock."""
    auto = kind == 'auto_block'
    return {
        'kind': kind, 'scope': 'ssh', 'id': r.pk, 'target_ip': r.target_ip,
        'at': (r.executed_at or r.created_at) if auto else r.requested_at,
        'requested_by': '' if auto else r.requested_by_username,
        'execution_status': r.execution_status, 'failure_kind': '' if auto else r.failure_kind,
        'failure_reason': r.failure_reason, 'command': r.command,
        'ufw_before_result': None if auto else r.ufw_before_result,
        'ufw_after_result': None if auto else r.ufw_after_result,
    }


def _web_action(r):
    """One row of Nginx web block/unblock history, in the same shape as _action."""
    return {
        'kind': f'web_{r.operation}', 'scope': 'web', 'id': r.pk, 'target_ip': r.target_ip, 'at': r.requested_at,
        'requested_by': r.requested_by_username, 'execution_status': r.execution_status,
        'failure_kind': r.failure_kind, 'failure_reason': r.failure_reason, 'command': r.command,
        'ufw_before_result': r.state_before_result, 'ufw_after_result': r.state_after_result,
        'http_check_status': r.http_check_status, 'http_check_result': r.http_check_result,
    }


def _history():
    rows = [_action('auto_block', r) for r in ResponseRecord.objects.filter(action='block_ssh').order_by('-id')[:HISTORY_LIMIT]]
    rows += [_action('manual_block', r) for r in ManualBlockRecord.objects.order_by('-id')[:HISTORY_LIMIT]]
    rows += [_action('unblock', r) for r in UnblockRecord.objects.order_by('-id')[:HISTORY_LIMIT]]
    rows += [_web_action(r) for r in WebBlockRecord.objects.order_by('-id')[:HISTORY_LIMIT]]
    return sorted(rows, key=lambda a: a['at'], reverse=True)[:HISTORY_LIMIT]


def _threats(requester_ip=None):
    """One row per alerted source IP, built only from stored records. No current firewall state here."""
    history = _history()
    risks, incidents, rules = {}, {}, {}
    for r in RiskResult.objects.order_by('score'):
        risks[r.source_ip] = {'score': r.score, 'level': r.level}  # highest score wins
    for i in Incident.objects.order_by('id'):
        incidents.setdefault(i.source_ip, []).append({'id': i.pk, 'risk_level': i.risk_level, 'risk_score': i.risk_score})
    for ip, rule in Alert.objects.values_list('source_ip', 'rule_type').distinct():
        rules.setdefault(ip, []).append(rule)
    threats = []
    for row in Alert.objects.values('source_ip').annotate(alert_count=Count('id'), latest=Max('occurred_at')):
        ip = row['source_ip']
        refused = read_only_reason(ip)
        web_refused = web_block.refusal(ip, 'block', requester_ip)
        block = latest_block(ip)
        threats.append({
            'ip': ip, 'is_fixture': is_fixture_ip(ip), 'rule_types': sorted(rules.get(ip, [])),
            'alert_count': row['alert_count'], 'latest_alert_at': row['latest'],
            'risk': risks.get(ip), 'incidents': incidents.get(ip, []),
            'actionable': not refused, 'read_only_kind': refused[0] if refused else '',
            'read_only_reason': refused[1] if refused else '',
            # History only: whether this system ever blocked the IP. Never the current UFW state.
            'has_past_block': block is not None,
            'last_action': next((a for a in history if a['target_ip'] == ip), None),
            # Nginx 8080 web block: any alerted IP passing web_block.refusal; current state comes from web-status.
            'web_actionable': not web_refused, 'web_read_only_kind': web_refused[0] if web_refused else '',
            'web_read_only_reason': web_refused[1] if web_refused else '',
            'web_unblock_allowed': not web_block.refusal(ip, 'unblock'),
        })
    return threats, history


@superuser_required
@require_GET
def threats_view(request):
    threats, history = _threats(request.META.get('REMOTE_ADDR'))
    try:
        targets, config_error = sorted(str(ip) for ip in approved_targets()), ''
    except ResponseConfigError as exc:
        targets, config_error = [], str(exc)
    try:
        web_private, web_config_error = [str(n) for n in web_block.private_ranges()], ''
    except ResponseConfigError as exc:
        web_private, web_config_error = [], str(exc)
    return JsonResponse({
        'threats': threats, 'history': history, 'blocked_port': f'{BLOCKED_PORT}/tcp',
        'unblock_enabled': getattr(settings, EXECUTE_SETTING, False) is True,
        'manual_block_enabled': getattr(settings, BLOCK_SETTING, False) is True,
        'approved_targets': targets, 'config_error': config_error,
        'web_port': f'{web_block.WEB_PORT}/tcp', 'web_block_enabled': getattr(settings, web_block.EXECUTE_SETTING, False) is True,
        'web_private_ranges': web_private, 'web_config_error': web_config_error,
        'overrides_error': getattr(settings, 'RESPONSE_OVERRIDES_ERROR', ''),
        'settings': {'unblock': EXECUTE_SETTING, 'manual_block': BLOCK_SETTING, 'targets': 'RESPONSE_MANUAL_TARGETS',
                     'web_block': web_block.EXECUTE_SETTING, 'web_private_ranges': web_block.PRIVATE_SETTING},
    })


@superuser_required
@csrf_protect
@require_POST
def ufw_status_view(request):
    """One read-only `ufw status`; states only for real (non-fixture) alerted IPs."""
    ips = [ip for ip in Alert.objects.values_list('source_ip', flat=True).distinct() if not is_fixture_ip(ip)]
    states, failure_kind, detail = read_ufw_states(ips)
    return JsonResponse({'states': states, 'failure_kind': failure_kind, 'detail': detail, 'checked_at': timezone.now()})


def _confirmed_ip(request):
    try:
        body = json.loads(request.body or b'{}')
        if body.get('confirm') is True and isinstance(body.get('ip'), str):
            return body['ip']
    except (ValueError, AttributeError):
        pass
    return None


def _ip_action(request, perform, done_state, done_outcome, skipped_outcome):
    ip = _confirmed_ip(request)
    if ip is None:
        return JsonResponse({'detail': '대상 IP와 명시적 확인(confirm)이 필요합니다. 명령을 보내지 않았습니다.'}, status=400)
    try:
        audit = perform(ip, request.user)
    except ActionRefused as exc:
        return JsonResponse({'outcome': 'refused', 'failure_kind': exc.kind, 'detail': exc.reason},
                            status=FAILURE_STATUS.get(exc.kind, 403))
    if isinstance(audit, WebBlockRecord):
        action, state, evidence = _web_action(audit), audit.state_after_result, audit.state_after_evidence
    else:
        action = _action('unblock' if isinstance(audit, UnblockRecord) else 'manual_block', audit)
        state, evidence = audit.ufw_after_result, audit.ufw_after_evidence
    if audit.execution_status == 'skipped':
        outcome, status = skipped_outcome, 200
    elif audit.execution_status == 'succeeded' and state == done_state:
        outcome, status = done_outcome, 200
    else:
        outcome, status = 'failed', FAILURE_STATUS.get(audit.failure_kind, 502)
    return JsonResponse({
        'outcome': outcome, 'detail': audit.failure_reason, 'failure_kind': audit.failure_kind,
        'action': action, 'ufw_state': state, 'ufw_evidence': evidence, 'checked_at': audit.completed_at,
    }, status=status)


@superuser_required
@csrf_protect
@require_POST
def threat_block_view(request):
    return _ip_action(request, manual_block, 'present', 'blocked', 'already_blocked')


@superuser_required
@csrf_protect
@require_POST
def threat_unblock_view(request):
    return _ip_action(request, unblock_ip, 'absent', 'unblocked', 'already_unblocked')


# ---- Nginx 8080 web block (events/web_block.py) -----------------------------------------------

@superuser_required
@csrf_protect
@require_POST
def web_status_view(request):
    """One read-only helper `status`; states only for real (non-fixture) alerted IPs."""
    ips = [ip for ip in Alert.objects.values_list('source_ip', flat=True).distinct() if not is_fixture_ip(ip)]
    states, failure_kind, detail = web_block.read_web_states(ips)
    return JsonResponse({'states': states, 'failure_kind': failure_kind, 'detail': detail, 'checked_at': timezone.now()})


@superuser_required
@csrf_protect
@require_POST
def threat_web_block_view(request):
    requester_ip = request.META.get('REMOTE_ADDR')
    return _ip_action(request, lambda ip, user: web_block.web_action(ip, 'block', user, requester_ip=requester_ip),
                      'present', 'blocked', 'already_blocked')


@superuser_required
@csrf_protect
@require_POST
def threat_web_unblock_view(request):
    return _ip_action(request, lambda ip, user: web_block.web_action(ip, 'unblock', user), 'absent', 'unblocked', 'already_unblocked')
