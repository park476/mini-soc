from rest_framework import serializers

from .models import SecurityEvent


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = (
            'id', 'source_type', 'event_time', 'source_ip', 'action', 'result',
            'request_path', 'http_status', 'ssh_evidence', 'raw_log', 'created_at',
        )
        read_only_fields = fields
