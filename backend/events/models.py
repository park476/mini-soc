from django.db import models
from django.utils import timezone


class SecurityEvent(models.Model):
    source_type = models.CharField(max_length=5, choices=[('nginx', 'nginx'), ('ssh', 'ssh')])
    event_time = models.DateTimeField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    action = models.TextField()
    result = models.TextField()
    request_path = models.TextField(blank=True)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    ssh_evidence = models.TextField(blank=True)
    raw_log = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


SOURCE_TYPES = [('nginx', 'nginx'), ('ssh', 'ssh')]


class NormalizationFailure(models.Model):
    source_type = models.CharField(max_length=5, choices=SOURCE_TYPES)
    raw_log = models.TextField()
    failure_reason = models.TextField()
    received_at = models.DateTimeField(default=timezone.now)


class LogSourceStatus(models.Model):
    source_type = models.CharField(max_length=5, choices=SOURCE_TYPES, unique=True)
    last_received_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    delivery_anomaly = models.BooleanField(default=False)


RULE_TYPES = [
    ('ssh_brute_force', 'ssh_brute_force'),
    ('nginx_scan', 'nginx_scan'),
    ('nginx_suspicious_path', 'nginx_suspicious_path'),
]


class Alert(models.Model):
    rule_type = models.CharField(max_length=32, choices=RULE_TYPES)
    source_ip = models.GenericIPAddressField()
    occurred_at = models.DateTimeField()
    rule_condition = models.TextField()
    evidence = models.TextField()
    # Last event that satisfied the rule; (rule_type, trigger_event) keeps re-runs idempotent.
    trigger_event = models.ForeignKey(SecurityEvent, on_delete=models.PROTECT, related_name='+')
    related_events = models.ManyToManyField(SecurityEvent, related_name='alerts')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['rule_type', 'trigger_event'], name='unique_alert_per_trigger'),
        ]
