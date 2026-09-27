"""Rule-based detection over stored SecurityEvents (T3).

Each rule groups events per source_ip in (event_time, id) order. Once a window meets the
threshold an Alert is produced and the window restarts, so the same input always yields the
same trigger events and re-running does not duplicate Alerts.
"""
from collections import deque
from datetime import timedelta

from django.db import transaction

from .models import Alert, SecurityEvent

WINDOW = timedelta(seconds=60)
SSH_FAILURE_THRESHOLD = 5
SCAN_DISTINCT_PATH_THRESHOLD = 10
SCAN_STATUSES = (403, 404)
SUSPICIOUS_PATHS = (
    '/.env', '/wp-admin', '/wp-login.php', '/admin',
    '/phpmyadmin', '/.git', '/config', '/backup',
)

SSH_CONDITION = f'source_type=ssh, result=failure, same source_ip, >= {SSH_FAILURE_THRESHOLD} within 60s'
SCAN_CONDITION = (f'source_type=nginx, http_status in 403/404, same source_ip, '
                  f'>= {SCAN_DISTINCT_PATH_THRESHOLD} distinct request_path within 60s')
SUSPICIOUS_CONDITION = 'source_type=nginx, request_path equals or is under one of ' + ', '.join(SUSPICIOUS_PATHS)


def _by_ip(queryset):
    groups = {}
    for event in queryset.exclude(source_ip=None).order_by('event_time', 'id'):
        groups.setdefault(event.source_ip, []).append(event)
    return groups


def _trim(window, now):
    while window and now - window[0].event_time > WINDOW:
        window.popleft()


def find_ssh_brute_force():
    events = SecurityEvent.objects.filter(source_type='ssh', result='failure')
    for ip, ordered in _by_ip(events).items():
        window = deque()
        for event in ordered:
            window.append(event)
            _trim(window, event.event_time)
            if len(window) >= SSH_FAILURE_THRESHOLD:
                matched = list(window)
                evidence = (f'{len(matched)} SSH authentication failures from {ip} between '
                            f'{matched[0].event_time.isoformat()} and {event.event_time.isoformat()}')
                yield 'ssh_brute_force', SSH_CONDITION, evidence, matched
                window.clear()


def find_nginx_scan():
    events = SecurityEvent.objects.filter(source_type='nginx', http_status__in=SCAN_STATUSES)
    for ip, ordered in _by_ip(events).items():
        window = deque()
        for event in ordered:
            window.append(event)
            _trim(window, event.event_time)
            paths = {e.request_path for e in window}
            if len(paths) >= SCAN_DISTINCT_PATH_THRESHOLD:
                matched = list(window)
                evidence = (f'{len(paths)} distinct paths with 403/404 from {ip} between '
                            f'{matched[0].event_time.isoformat()} and {event.event_time.isoformat()}')
                yield 'nginx_scan', SCAN_CONDITION, evidence, matched
                window.clear()


def is_suspicious_path(path):
    return any(path == p or path.startswith(p + '/') for p in SUSPICIOUS_PATHS)


def find_nginx_suspicious_path():
    for ip, ordered in _by_ip(SecurityEvent.objects.filter(source_type='nginx')).items():
        for event in ordered:
            if is_suspicious_path(event.request_path):
                evidence = f'{ip} requested {event.request_path} (HTTP {event.http_status})'
                yield 'nginx_suspicious_path', SUSPICIOUS_CONDITION, evidence, [event]


RULES = (find_ssh_brute_force, find_nginx_scan, find_nginx_suspicious_path)


@transaction.atomic
def run_detection():
    """Evaluate all rules and store new Alerts. Returns the number of Alerts created."""
    created = 0
    for rule in RULES:
        for rule_type, condition, evidence, matched in rule():
            trigger = matched[-1]
            alert, is_new = Alert.objects.get_or_create(
                rule_type=rule_type, trigger_event=trigger,
                defaults={
                    'source_ip': trigger.source_ip, 'occurred_at': trigger.event_time,
                    'rule_condition': condition, 'evidence': evidence,
                },
            )
            if is_new:
                alert.related_events.set(matched)
                created += 1
    return created
