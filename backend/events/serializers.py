from rest_framework import serializers

from .models import (
    Alert, CorrelationResult, Incident, LogSourceStatus, ResponseRecord, ResponseVerification, RiskResult,
    SecurityEvent,
)


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


class ResponseVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ResponseVerification
        fields = (
            'id', 'ufw_rule_result', 'ufw_rule_present', 'ufw_check_evidence',
            'kali_ssh_reconnect_result', 'reconnect_failed', 'reconnect_check_evidence',
            'verification_status', 'success', 'verified_at',
        )
        read_only_fields = fields


class ResponseRecordSerializer(serializers.ModelSerializer):
    triggering_alert = AlertSummarySerializer(read_only=True)
    triggering_alert_id = serializers.IntegerField(read_only=True)
    verification = serializers.SerializerMethodField()
    verification_count = serializers.SerializerMethodField()

    class Meta:
        model = ResponseRecord
        fields = (
            'id', 'triggering_alert_id', 'triggering_alert', 'target_ip', 'action', 'allowlist_result',
            'allowlist_detail', 'execution_status', 'victim', 'command', 'execution_result', 'failure_reason',
            'executed_at', 'completed_at', 'created_at', 'verification', 'verification_count',
        )
        read_only_fields = fields

    def _verifications(self, obj):
        return sorted(obj.verifications.all(), key=lambda v: (v.verified_at, v.pk))

    def get_verification(self, obj):
        """Latest verification, or null when none has been recorded."""
        latest = self._verifications(obj)
        return ResponseVerificationSerializer(latest[-1]).data if latest else None

    def get_verification_count(self, obj):
        return len(self._verifications(obj))


class LogSourceStatusSerializer(serializers.ModelSerializer):
    recorded = serializers.SerializerMethodField()

    class Meta:
        model = LogSourceStatus
        fields = ('source_type', 'recorded', 'last_received_at', 'last_error', 'delivery_anomaly')
        read_only_fields = fields

    def get_recorded(self, obj):
        return obj.pk is not None
