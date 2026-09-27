from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import SOURCE_TYPES, Alert, Incident, LogSourceStatus, ResponseRecord, SecurityEvent
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
