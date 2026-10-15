"""PB-01: limited automatic Nginx 8080 web block of nginx_scan attackers, with TTL auto-unblock.

Runs inside the existing run_analysis loop (no admin button). Two independent phases:

  block   (gated by RESPONSE_AUTO_WEB_EXECUTE): for each recent nginx_scan Alert not yet handled,
          block the source IP once, reusing events/web_block.web_action and the victim web helper.
  expire  (gated by RESPONSE_WEB_BLOCK_EXECUTE, independent of the auto switch): auto-unblock this
          playbook's own blocks once their TTL passes, so turning the auto switch off never strands
          an already auto-blocked IP. A manual recovery path (admin panel / mini PC) always remains.

Safety for shared public IPs: only Alerts newer than RESPONSE_AUTO_WEB_MAX_ALERT_AGE are candidates
(no bulk block of old Alerts at activation), at most RESPONSE_AUTO_WEB_HOURLY_LIMIT blocks per rolling
hour, every protected/allowlisted/special address is refused, and each block carries a TTL. Dedup is by
trigger_alert (one handling per Alert) plus web_action's live-blocklist check; a crash mid-send leaves
the Alert unhandled and the next cycle records a 'skipped' instead of a duplicate rule. A manual block
made after an auto block takes ownership of the IP and is never auto-unblocked.
"""
import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Exists, OuterRef
from django.utils import timezone

from config import response_overrides

from .models import Alert, WebBlockRecord
from .web_block import EXECUTE_SETTING as WEB_EXECUTE_SETTING, web_action

logger = logging.getLogger('events.web_auto')

TRIGGER_RULE = 'nginx_scan'
AUTO_EXECUTE_SETTING = 'RESPONSE_AUTO_WEB_EXECUTE'


def _candidate_alert_ids(now):
    """Recent nginx_scan Alerts with no WebBlockRecord yet, oldest first."""
    cutoff = now - timedelta(seconds=settings.RESPONSE_AUTO_WEB_MAX_ALERT_AGE)
    handled = WebBlockRecord.objects.filter(trigger_alert=OuterRef('pk'))
    return list(Alert.objects.filter(rule_type=TRIGGER_RULE, created_at__gte=cutoff)
                .exclude(Exists(handled)).order_by('created_at', 'id').values_list('pk', flat=True))


def _blocks_this_hour(now):
    return WebBlockRecord.objects.filter(origin='auto', operation='block', execution_status='succeeded',
                                         executed_at__gte=now - timedelta(hours=1)).count()


def _record_rate_limited(alert, now):
    return WebBlockRecord.objects.create(
        operation='block', origin='auto', trigger_alert=alert, requested_by_username='auto',
        target_ip=str(alert.source_ip), execution_status='skipped', failure_kind='rate_limited',
        failure_reason=f'Hourly automatic web-block limit ({settings.RESPONSE_AUTO_WEB_HOURLY_LIMIT}) reached; '
                       'this Alert was not auto-blocked.', completed_at=now)


def _block_new(executor, now):
    summary = {'enabled': True, 'blocked': 0, 'skipped': 0, 'failed': 0, 'rate_limited': 0}
    for alert_id in _candidate_alert_ids(now):
        try:
            with transaction.atomic():
                # Lock the Alert so a second worker cannot process it at the same time; re-check inside.
                alert = Alert.objects.select_for_update().get(pk=alert_id)
                if WebBlockRecord.objects.filter(trigger_alert=alert).exists():
                    continue
                if _blocks_this_hour(now) >= settings.RESPONSE_AUTO_WEB_HOURLY_LIMIT:
                    _record_rate_limited(alert, now)
                    summary['rate_limited'] += 1
                    continue
                record = web_action(alert.source_ip, 'block', origin='auto', trigger_alert=alert,
                                    expires_at=now + timedelta(seconds=settings.RESPONSE_AUTO_WEB_TTL),
                                    execute_setting=AUTO_EXECUTE_SETTING, executor=executor)
        except Exception:
            logger.exception('PB-01 block failed for alert %s', alert_id)
            summary['failed'] += 1
            continue
        if record.execution_status == 'succeeded':
            summary['blocked'] += 1
        elif record.execution_status == 'skipped':
            summary['skipped'] += 1
        else:
            summary['failed'] += 1
    return summary


def active_auto_blocks(now=None):
    """Succeeded automatic blocks that are still the IP's latest block and not yet released."""
    now = now or timezone.now()
    active = []
    for block in WebBlockRecord.objects.filter(origin='auto', operation='block',
                                               execution_status='succeeded').order_by('-executed_at', '-id'):
        latest_block = (WebBlockRecord.objects.filter(target_ip=block.target_ip, operation='block',
                        execution_status='succeeded').order_by('-executed_at', '-id').first())
        if latest_block.pk != block.pk:
            continue  # a newer (possibly manual) block owns this IP now
        released = WebBlockRecord.objects.filter(target_ip=block.target_ip, operation='unblock',
                   execution_status='succeeded', executed_at__gte=block.executed_at).exists()
        if not released:
            active.append(block)
    return active


def _expire(executor, now):
    summary = {'due': 0, 'unblocked': 0, 'failed': 0, 'deferred': 0}
    web_enabled = getattr(settings, WEB_EXECUTE_SETTING, False) is True
    for block in active_auto_blocks(now):
        if block.expires_at is None or block.expires_at > now:
            continue
        summary['due'] += 1
        if not web_enabled:
            # Independent recovery path: admin panel unblock, or enabling RESPONSE_WEB_BLOCK_EXECUTE.
            summary['deferred'] += 1
            continue
        try:
            record = web_action(block.target_ip, 'unblock', origin='auto', trigger_alert=block.trigger_alert,
                                execute_setting=WEB_EXECUTE_SETTING, executor=executor)
        except Exception:
            logger.exception('PB-01 TTL unblock failed for %s', block.target_ip)
            summary['failed'] += 1
            continue
        summary['unblocked' if record.execution_status in ('succeeded', 'skipped') else 'failed'] += 1
    return summary


def run_web_auto(executor=None, now=None):
    """One PB-01 pass: refresh the override switches, auto-unblock expired blocks, then block new ones."""
    response_overrides.refresh()
    now = now or timezone.now()
    summary = {'expire': _expire(executor, now)}
    if getattr(settings, AUTO_EXECUTE_SETTING, False) is True:
        summary['block'] = _block_new(executor, now)
    else:
        summary['block'] = {'enabled': False}
    return summary
