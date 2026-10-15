from django.conf import settings
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from . import web_auto
from .models import SOURCE_TYPES, Alert, Incident, LogSourceStatus, ResponseRecord, SecurityEvent, WebBlockRecord
from .serializers import (
    AlertSerializer, IncidentSerializer, LogSourceStatusSerializer, ResponseRecordSerializer,
    SecurityEventSerializer,
)


class SecurityEventListView(ListAPIView):
    queryset = SecurityEvent.objects.order_by('-event_time', '-id')
    serializer_class = SecurityEventSerializer


class SecurityEventDetailView(RetrieveAPIView):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer


class AlertListView(ListAPIView):
    queryset = Alert.objects.prefetch_related('related_events').order_by('-occurred_at', '-id')
    serializer_class = AlertSerializer


class AlertDetailView(RetrieveAPIView):
    queryset = Alert.objects.prefetch_related('related_events')
    serializer_class = AlertSerializer


INCIDENTS = Incident.objects.select_related('correlation', 'risk_result').prefetch_related(
    'alerts', 'correlation__alerts',
)


class IncidentListView(ListAPIView):
    queryset = INCIDENTS.order_by('-occurred_at', '-id')
    serializer_class = IncidentSerializer


class IncidentDetailView(RetrieveAPIView):
    queryset = INCIDENTS
    serializer_class = IncidentSerializer


RESPONSES = ResponseRecord.objects.select_related('triggering_alert').prefetch_related('verifications')


class ResponseListView(ListAPIView):
    queryset = RESPONSES.order_by('-created_at', '-id')
    serializer_class = ResponseRecordSerializer


class ResponseDetailView(RetrieveAPIView):
    queryset = RESPONSES
    serializer_class = ResponseRecordSerializer


def _web_auto_record(r):
    alert = r.trigger_alert
    return {
        'id': r.pk, 'operation': r.operation, 'target_ip': r.target_ip, 'origin': r.origin,
        'trigger_alert_id': r.trigger_alert_id,
        'trigger_alert': ({'id': alert.pk, 'rule_type': alert.rule_type, 'source_ip': alert.source_ip,
                           'occurred_at': alert.occurred_at} if alert else None),
        'execution_status': r.execution_status, 'failure_kind': r.failure_kind, 'failure_reason': r.failure_reason,
        'requested_at': r.requested_at, 'executed_at': r.executed_at, 'expires_at': r.expires_at,
        # Three separate verification facts: the command result (execution_status), the blocklist
        # re-read (state_after_result), and the attacker's real HTTP status (http_check_*).
        'blocklist_state': r.state_after_result,
        'http_check_status': r.http_check_status, 'http_check_result': r.http_check_result,
        'http_checked_at': r.http_checked_at,
    }


def _web_auto_cases(records):
    """One case per automatic block, with the matching TTL unblock of the same attack, newest first.
    Pairs by trigger_alert and target_ip so the timeline is built only from real linked records."""
    blocks = [r for r in records if r['operation'] == 'block']
    unblocks = [r for r in records if r['operation'] == 'unblock']
    cases = []
    for b in blocks:
        unblock = next((u for u in unblocks if u['trigger_alert_id'] == b['trigger_alert_id']
                        and u['target_ip'] == b['target_ip']
                        and (u['executed_at'] or '') >= (b['executed_at'] or '')), None)
        cases.append({'key': f"b{b['id']}", 'target_ip': b['target_ip'],
                      'alert': b['trigger_alert'], 'block': b, 'unblock': unblock})
    return cases


class WebAutoStatusView(APIView):
    """Read-only PB-01 status: the real switch state and stored records, never a fixed 'done' claim."""

    def get(self, request):
        auto_records = (WebBlockRecord.objects.filter(origin='auto')
                        .select_related('trigger_alert').order_by('-id'))
        records = [_web_auto_record(r) for r in auto_records[:50]]
        blocks_succeeded = auto_records.filter(operation='block', execution_status='succeeded')
        latest = auto_records.exclude(executed_at=None).order_by('-executed_at').first()
        return Response({
            'playbook': 'PB-01 nginx_scan 자동 웹 차단',
            # Config state only (not process liveness): the loop refreshes these from the override file.
            'enabled': getattr(settings, web_auto.AUTO_EXECUTE_SETTING, False) is True,
            'web_block_enabled': getattr(settings, 'RESPONSE_WEB_BLOCK_EXECUTE', False) is True,
            'overrides_error': getattr(settings, 'RESPONSE_OVERRIDES_ERROR', ''),
            'policy': {
                'trigger_rule': web_auto.TRIGGER_RULE,
                'max_alert_age_seconds': settings.RESPONSE_AUTO_WEB_MAX_ALERT_AGE,
                'hourly_limit': settings.RESPONSE_AUTO_WEB_HOURLY_LIMIT,
                'ttl_seconds': settings.RESPONSE_AUTO_WEB_TTL,
            },
            'counts': {
                'total': auto_records.count(),
                'blocks_succeeded': blocks_succeeded.count(),
                'http_verified': auto_records.filter(operation='block', http_check_result='success').count(),
                'unblocks_succeeded': auto_records.filter(operation='unblock', execution_status='succeeded').count(),
                'active': len(web_auto.active_auto_blocks()),
                'latest_at': latest.executed_at if latest else None,
            },
            'records': records,
            'cases': _web_auto_cases(records),
        })


DASHBOARD_RECENT = 6


class DashboardView(APIView):
    """Read-only summary of stored records (docs 04 §5); computes no new analysis."""

    def get(self, request):
        statuses = {s.source_type: s for s in LogSourceStatus.objects.all()}
        events = SecurityEvent.objects.all()
        incidents = Incident.objects.all()
        recent = slice(0, DASHBOARD_RECENT)
        return Response({
            # One entry per source; recorded=false means no receive has been stored yet.
            'source_status': [
                LogSourceStatusSerializer(statuses.get(source) or LogSourceStatus(source_type=source)).data
                for source, _ in SOURCE_TYPES
            ],
            'counts': {
                'events': events.count(),
                'nginx_events': events.filter(source_type='nginx').count(),
                'ssh_events': events.filter(source_type='ssh').count(),
                'alerts': Alert.objects.count(),
                'incidents': incidents.count(),
                'high_incidents': incidents.filter(risk_level='High').count(),
                'responses': ResponseRecord.objects.count(),
            },
            'recent_events': SecurityEventSerializer(events.order_by('-event_time', '-id')[recent], many=True).data,
            'recent_alerts': AlertSerializer(
                Alert.objects.prefetch_related('related_events').order_by('-occurred_at', '-id')[recent], many=True,
            ).data,
            'recent_incidents': IncidentSerializer(INCIDENTS.order_by('-occurred_at', '-id')[recent], many=True).data,
            'recent_responses': ResponseRecordSerializer(RESPONSES.order_by('-created_at', '-id')[recent], many=True).data,
        })
