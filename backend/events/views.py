from rest_framework.generics import ListAPIView, RetrieveAPIView

from .models import Alert, Incident, ResponseRecord, SecurityEvent
from .serializers import (
    AlertSerializer, IncidentSerializer, ResponseRecordSerializer, SecurityEventSerializer,
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
