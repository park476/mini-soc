from rest_framework import serializers

from .models import Alert, CorrelationResult, Incident, RiskResult, SecurityEvent


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


class AlertSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ('id', 'rule_type', 'occurred_at', 'evidence')
        read_only_fields = fields


class CorrelationResultSerializer(serializers.ModelSerializer):
    alert_ids = serializers.PrimaryKeyRelatedField(source='alerts', many=True, read_only=True)

    class Meta:
        model = CorrelationResult
        fields = (
            'id', 'source_ip', 'correlation_type', 'alert_ids', 'window_start', 'window_end',
            'matched', 'matched_at', 'evidence', 'judged_at',
        )
        read_only_fields = fields


class RiskResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskResult
        fields = ('id', 'score', 'level', 'rule_types', 'correlation_applied', 'score_basis', 'judged_at')
        read_only_fields = fields


class IncidentSerializer(serializers.ModelSerializer):
    alert_ids = serializers.PrimaryKeyRelatedField(source='alerts', many=True, read_only=True)
    alerts = AlertSummarySerializer(many=True, read_only=True)
    correlation_result_id = serializers.PrimaryKeyRelatedField(source='correlation', read_only=True)
    correlation = CorrelationResultSerializer(read_only=True)
    risk_result = RiskResultSerializer(read_only=True)

    class Meta:
        model = Incident
        fields = (
            'id', 'source_ip', 'occurred_at', 'risk_score', 'risk_level', 'creation_reason',
            'alert_ids', 'alerts', 'correlation_result_id', 'correlation', 'risk_result', 'created_at',
        )
        read_only_fields = fields
