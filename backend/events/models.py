from django.conf import settings
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


class CorrelationResult(models.Model):
    """One judgment scope for a source_ip; see events/correlation.py for how scopes are formed."""
    source_ip = models.GenericIPAddressField()
    # First SSH Alert of the scope (first Nginx Alert if none); keys idempotent re-runs.
    anchor_alert = models.OneToOneField(Alert, on_delete=models.PROTECT, related_name='+')
    alerts = models.ManyToManyField(Alert, related_name='correlations')
    correlation_type = models.CharField(max_length=64)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    matched = models.BooleanField()
    matched_at = models.DateTimeField(null=True, blank=True)
    evidence = models.TextField()
    judged_at = models.DateTimeField(auto_now=True)


RISK_LEVELS = [('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')]


class RiskResult(models.Model):
    correlation = models.OneToOneField(CorrelationResult, on_delete=models.CASCADE, related_name='risk')
    source_ip = models.GenericIPAddressField()
    score = models.PositiveSmallIntegerField()
    level = models.CharField(max_length=6, choices=RISK_LEVELS)
    rule_types = models.JSONField()
    correlation_applied = models.BooleanField()
    score_basis = models.JSONField()
    judged_at = models.DateTimeField(auto_now=True)


class Incident(models.Model):
    correlation = models.OneToOneField(CorrelationResult, on_delete=models.PROTECT, related_name='incident')
    risk_result = models.ForeignKey(RiskResult, on_delete=models.PROTECT, related_name='+')
    source_ip = models.GenericIPAddressField()
    occurred_at = models.DateTimeField()
    # Snapshot at creation time; the linked RiskResult may be re-judged later.
    risk_score = models.PositiveSmallIntegerField()
    risk_level = models.CharField(max_length=6, choices=RISK_LEVELS)
    alerts = models.ManyToManyField(Alert, related_name='incidents')
    creation_reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class ResponseRecord(models.Model):
    """Automatic SSH block triggered by an ssh_brute_force Alert. 'succeeded' means only that the
    UFW command ran successfully; the actual effect is recorded in ResponseVerification."""
    ALLOWLIST_RESULTS = [('excluded', 'excluded'), ('not_excluded', 'not_excluded'), ('unknown', 'unknown')]
    EXECUTION_STATUSES = [
        ('succeeded', 'succeeded'), ('failed', 'failed'), ('skipped', 'skipped'), ('unknown', 'unknown'),
    ]

    triggering_alert = models.OneToOneField(Alert, on_delete=models.PROTECT, related_name='response')
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    action = models.CharField(max_length=16, choices=[('block_ssh', 'block_ssh')], default='block_ssh')
    allowlist_result = models.CharField(max_length=12, choices=ALLOWLIST_RESULTS)
    allowlist_detail = models.TextField(blank=True)
    execution_status = models.CharField(max_length=9, choices=EXECUTION_STATUSES)
    victim = models.TextField(blank=True)
    command = models.TextField(blank=True)
    execution_result = models.TextField(blank=True)
    failure_reason = models.TextField(blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class ResponseVerification(models.Model):
    UFW_RESULTS = [('present', 'present'), ('absent', 'absent'), ('unchecked', 'unchecked')]
    RECONNECT_RESULTS = [('failed', 'failed'), ('succeeded', 'succeeded'), ('unchecked', 'unchecked')]
    STATUSES = [('success', 'success'), ('failed', 'failed'), ('unverified', 'unverified')]

    response = models.ForeignKey(ResponseRecord, on_delete=models.PROTECT, related_name='verifications')
    ufw_rule_result = models.CharField(max_length=9, choices=UFW_RESULTS)
    ufw_check_evidence = models.TextField(blank=True)
    kali_ssh_reconnect_result = models.CharField(max_length=9, choices=RECONNECT_RESULTS)
    reconnect_check_evidence = models.TextField(blank=True)
    verification_status = models.CharField(max_length=10, choices=STATUSES)
    verified_at = models.DateTimeField(auto_now_add=True)

    @property
    def ufw_rule_present(self):
        return self.ufw_rule_result == 'present'

    @property
    def reconnect_failed(self):
        return self.kali_ssh_reconnect_result == 'failed'

    @property
    def success(self):
        return self.verification_status == 'success'

    def save(self, *args, **kwargs):
        # Success requires both checks; a single negative result is a failure, anything else unverified.
        if self.ufw_rule_present and self.reconnect_failed:
            self.verification_status = 'success'
        elif self.ufw_rule_result == 'absent' or self.kali_ssh_reconnect_result == 'succeeded':
            self.verification_status = 'failed'
        else:
            self.verification_status = 'unverified'
        super().save(*args, **kwargs)


class UnblockRecord(models.Model):
    """Audit of one administrator-requested SSH unblock. Never edits the ResponseRecord it refers to.
    execution_status covers only the UFW delete command; the UFW re-check and the Kali SSH reconnect
    are separate verification items."""
    EXECUTION_STATUSES = [
        ('succeeded', 'succeeded'), ('failed', 'failed'), ('skipped', 'skipped'), ('unknown', 'unknown'),
    ]
    FAILURE_KINDS = [
        ('', 'none'), ('not_eligible', 'not_eligible'), ('invalid_ip', 'invalid_ip'), ('config', 'config'),
        ('ssh_error', 'ssh_error'), ('sudo_denied', 'sudo_denied'), ('timeout', 'timeout'),
        ('command_failed', 'command_failed'), ('rule_still_present', 'rule_still_present'),
    ]
    UFW_RESULTS = ResponseVerification.UFW_RESULTS
    RECONNECT_RESULTS = ResponseVerification.RECONNECT_RESULTS

    # Exactly one source block: an automatic ResponseRecord or an administrator's ManualBlockRecord.
    response = models.ForeignKey(ResponseRecord, on_delete=models.PROTECT, related_name='unblocks', null=True, blank=True)
    manual_block = models.ForeignKey('ManualBlockRecord', on_delete=models.PROTECT, related_name='unblocks',
                                     null=True, blank=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='+')
    requested_by_username = models.CharField(max_length=150)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    execution_status = models.CharField(max_length=9, choices=EXECUTION_STATUSES, default='failed')
    failure_kind = models.CharField(max_length=20, choices=FAILURE_KINDS, blank=True)
    failure_reason = models.TextField(blank=True)
    victim = models.TextField(blank=True)
    command = models.TextField(blank=True)
    execution_result = models.TextField(blank=True)
    ufw_before_result = models.CharField(max_length=9, choices=UFW_RESULTS, default='unchecked')
    ufw_before_evidence = models.TextField(blank=True)
    ufw_after_result = models.CharField(max_length=9, choices=UFW_RESULTS, default='unchecked')
    ufw_after_evidence = models.TextField(blank=True)
    # Entered from a real observation on the Kali host; never inferred from the command result.
    kali_ssh_reconnect_result = models.CharField(max_length=9, choices=RECONNECT_RESULTS, default='unchecked')
    reconnect_check_evidence = models.TextField(blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)


class ManualBlockRecord(models.Model):
    """Audit of one administrator-requested SSH (22/tcp) block or re-block of an approved IP.
    Separate from the automatic ResponseRecord, which stays one per Alert and is never rewritten."""
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='+')
    requested_by_username = models.CharField(max_length=150)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    execution_status = models.CharField(max_length=9, choices=UnblockRecord.EXECUTION_STATUSES, default='failed')
    failure_kind = models.CharField(max_length=20, blank=True)
    failure_reason = models.TextField(blank=True)
    victim = models.TextField(blank=True)
    command = models.TextField(blank=True)
    execution_result = models.TextField(blank=True)
    ufw_before_result = models.CharField(max_length=9, choices=ResponseVerification.UFW_RESULTS, default='unchecked')
    ufw_before_evidence = models.TextField(blank=True)
    ufw_after_result = models.CharField(max_length=9, choices=ResponseVerification.UFW_RESULTS, default='unchecked')
    ufw_after_evidence = models.TextField(blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)


class WebBlockRecord(models.Model):
    """Audit of one administrator-requested Nginx web (8080) block or unblock (events/web_block.py).
    execution_status covers only the helper command; the blocklist re-check and the attacker's
    observed HTTP status (403 while blocked, 200 after unblock) are separate verification items."""
    OPERATIONS = [('block', 'block'), ('unblock', 'unblock')]
    STATE_RESULTS = ResponseVerification.UFW_RESULTS  # present / absent / unchecked in the Nginx blocklist
    HTTP_CHECK_RESULTS = [('success', 'success'), ('failed', 'failed'), ('unchecked', 'unchecked')]

    operation = models.CharField(max_length=7, choices=OPERATIONS)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='+')
    requested_by_username = models.CharField(max_length=150)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    execution_status = models.CharField(max_length=9, choices=UnblockRecord.EXECUTION_STATUSES, default='failed')
    failure_kind = models.CharField(max_length=20, blank=True)
    failure_reason = models.TextField(blank=True)
    victim = models.TextField(blank=True)
    command = models.TextField(blank=True)
    execution_result = models.TextField(blank=True)
    state_before_result = models.CharField(max_length=9, choices=STATE_RESULTS, default='unchecked')
    state_before_evidence = models.TextField(blank=True)
    state_after_result = models.CharField(max_length=9, choices=STATE_RESULTS, default='unchecked')
    state_after_evidence = models.TextField(blank=True)
    # Entered from a real request made on the attacker host; never inferred from the command result.
    http_check_status = models.PositiveSmallIntegerField(null=True, blank=True)
    http_check_result = models.CharField(max_length=9, choices=HTTP_CHECK_RESULTS, default='unchecked')
    http_check_evidence = models.TextField(blank=True)
    http_checked_at = models.DateTimeField(null=True, blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
