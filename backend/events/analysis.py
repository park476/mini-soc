"""One analysis cycle over stored data (automatic loop for run_analysis).

Order: detection -> response (only when RESPONSE_EXECUTE is enabled) -> web-auto (PB-01) ->
correlation/risk/Incident. Response is triggered by ssh_brute_force Alerts and does not wait for
correlation. Each step reuses the existing idempotent module, so re-running a cycle over the same data
creates nothing new. The collector never calls this; collection and analysis run as separate processes.
"""
import logging
from collections import Counter

from django.conf import settings

from .correlation import run_correlation
from .detection import run_detection
from .response import run_responses
from .web_auto import run_web_auto

logger = logging.getLogger('events.analysis')


def run_cycle(executor=None):
    """Run each step, logging (not raising) failures. Returns a summary dict with an 'errors' list."""
    summary = {'alerts_created': None, 'response': None, 'web_auto': None, 'correlation': None, 'errors': []}

    def step(name, func):
        try:
            return func()
        except Exception as exc:  # keep later steps and the loop alive; the error is reported
            logger.exception('Analysis step %s failed', name)
            summary['errors'].append(f'{name}: {exc}')
            return None

    summary['alerts_created'] = step('detection', run_detection)
    if settings.RESPONSE_EXECUTE:
        records = step('response', lambda: run_responses(executor=executor))
        if records is not None:
            summary['response'] = {'enabled': True, 'processed': len(records),
                                   'statuses': dict(Counter(r.execution_status for r in records))}
    else:
        summary['response'] = {'enabled': False}
    # PB-01 refreshes the override switch itself, so it runs every cycle; it decides internally whether
    # to block, and always handles TTL auto-unblock. A failure here must not stop correlation.
    summary['web_auto'] = step('web_auto', lambda: run_web_auto(executor=executor))
    summary['correlation'] = step('correlation', run_correlation)
    return summary


def format_summary(summary):
    parts = []
    alerts = summary['alerts_created']
    parts.append(f'alerts created {alerts}' if alerts is not None else 'detection failed')
    response = summary['response']
    if response is None:
        parts.append('response failed')
    elif not response['enabled']:
        parts.append('response disabled (RESPONSE_EXECUTE is not true)')
    else:
        statuses = ', '.join(f'{k} {v}' for k, v in sorted(response['statuses'].items()))
        parts.append(f'response processed {response["processed"]}' + (f' ({statuses})' if statuses else ''))
    wa = summary['web_auto']
    if wa is None:
        parts.append('web-auto failed')
    else:
        block = 'off' if not wa['block'].get('enabled') else f"blocked {wa['block']['blocked']}/skipped {wa['block']['skipped']}"
        parts.append(f"web-auto ({block}; expired {wa['expire']['unblocked']})")
    c = summary['correlation']
    if c is None:
        parts.append('correlation failed')
    else:
        parts.append(f'correlations created {c["created"]}/updated {c["updated"]}/unchanged {c["unchanged"]}'
                     f'/removed {c["removed"]}; incidents created {c["incidents"]}')
    return 'Analysis cycle: ' + '; '.join(parts)
