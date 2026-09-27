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
