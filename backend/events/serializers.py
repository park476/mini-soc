from rest_framework import serializers

from .models import Alert, SecurityEvent


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = (
            'id', 'source_type', 'event_time', 'source_ip', 'action', 'result',
            'request_path', 'http_status', 'ssh_evidence', 'raw_log', 'created_at',
        )
        read_only_fields = fields


class AlertSerializer(serializers.ModelSerializer):
    related_event_ids = serializers.PrimaryKeyRelatedField(
        source='related_events', many=True, read_only=True,
    )

    class Meta:
        model = Alert
        fields = (
            'id', 'rule_type', 'source_ip', 'occurred_at', 'rule_condition', 'evidence',
            'trigger_event', 'related_event_ids', 'created_at',
        )
        read_only_fields = fields
