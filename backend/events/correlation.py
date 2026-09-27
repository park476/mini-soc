"""Correlation, risk scoring and Incident creation over stored Alerts (T4).

Judgment scope (per source_ip, alerts in (occurred_at, id) order):
- SSH scope: the first ssh_brute_force Alert not yet grouped anchors a scope that takes every
  later ssh_brute_force Alert within 10 minutes of it, plus every Nginx Alert within 10 minutes
  of any of those SSH Alerts. Correlation matches when that Nginx set is not empty.
- Nginx-only scope: Nginx Alerts outside every SSH scope are grouped greedily into 10-minute
  windows from their first Alert. They never match.
Each scope yields one CorrelationResult keyed by its anchor Alert (first SSH Alert, else first
Nginx Alert) and one RiskResult, so re-running updates the same rows instead of adding new ones.
"""
from datetime import timedelta

from django.db import transaction

from .models import Alert, CorrelationResult, Incident, RiskResult

CORRELATION_WINDOW = timedelta(minutes=10)
CORRELATION_TYPE = 'ssh_brute_force+nginx'
SSH_RULE = 'ssh_brute_force'
NGINX_RULES = ('nginx_scan', 'nginx_suspicious_path')
RULE_SCORES = {'ssh_brute_force': 40, 'nginx_scan': 30, 'nginx_suspicious_path': 20}
CORRELATION_BONUS = 30
MAX_SCORE = 100
INCIDENT_MIN_SCORE = 70


def risk_level(score):
    if score >= 70:
        return 'High'
    if score >= 40:
        return 'Medium'
    return 'Low'


def compute_risk(rule_types, correlated):
    """Each rule type counts once; +30 when correlated; capped at 100."""
    types = sorted(set(rule_types) & RULE_SCORES.keys())
    rule_scores = {t: RULE_SCORES[t] for t in types}
    bonus = CORRELATION_BONUS if correlated else 0
    uncapped = sum(rule_scores.values()) + bonus
    score = min(uncapped, MAX_SCORE)
    basis = {'rule_scores': rule_scores, 'correlation_bonus': bonus, 'uncapped': uncapped, 'cap': MAX_SCORE}
    return score, risk_level(score), types, basis


def _near(a, b):
    return abs(a.occurred_at - b.occurred_at) <= CORRELATION_WINDOW


def build_scopes(alerts):
    """alerts: one source_ip's Alerts sorted by (occurred_at, id). Returns list of (ssh, nginx)."""
    ssh = [a for a in alerts if a.rule_type == SSH_RULE]
    nginx = [a for a in alerts if a.rule_type in NGINX_RULES]
    scopes, covered, i = [], set(), 0
    while i < len(ssh):
        group = [a for a in ssh[i:] if a.occurred_at - ssh[i].occurred_at <= CORRELATION_WINDOW]
        i += len(group)
        paired = [n for n in nginx if any(_near(n, s) for s in group)]
        covered.update(n.pk for n in paired)
        scopes.append((group, paired))
    rest = [n for n in nginx if n.pk not in covered]
    while rest:
        group = [n for n in rest if n.occurred_at - rest[0].occurred_at <= CORRELATION_WINDOW]
        rest = rest[len(group):]
        scopes.append(([], group))
    return scopes


def _describe(ip, ssh, nginx):
    if ssh and nginx:
        pairs = []
        for n in nginx:
            s = min((s for s in ssh if _near(n, s)), key=lambda s: abs(n.occurred_at - s.occurred_at))
            delta = int(abs(n.occurred_at - s.occurred_at).total_seconds())
            pairs.append(f'{SSH_RULE} alert #{s.pk} and {n.rule_type} alert #{n.pk} ({delta}s apart)')
        matched_at = min(max(s.occurred_at, n.occurred_at) for n in nginx for s in ssh if _near(n, s))
        return True, matched_at, f'Same source_ip {ip} within 10 minutes: ' + '; '.join(pairs)
    if ssh:
        return False, None, f'No nginx_scan or nginx_suspicious_path alert from {ip} within 10 minutes of the SSH alerts'
    return False, None, f'No ssh_brute_force alert from {ip} within 10 minutes of these Nginx alerts'


def _save(instance, fields):
    changed = [k for k, v in fields.items() if getattr(instance, k) != v]
    for k in changed:
        setattr(instance, k, fields[k])
    if changed or instance.pk is None:
        instance.save()
    return bool(changed)


def _judge(ip, ssh, nginx, counts):
    alerts = sorted(ssh + nginx, key=lambda a: (a.occurred_at, a.pk))
    matched, matched_at, evidence = _describe(ip, ssh, nginx)
    anchor = ssh[0] if ssh else nginx[0]
    correlation = CorrelationResult.objects.filter(anchor_alert=anchor).first()
    is_new = correlation is None
    correlation = correlation or CorrelationResult(anchor_alert=anchor)
    changed = _save(correlation, {
        'source_ip': ip, 'correlation_type': CORRELATION_TYPE,
        'window_start': alerts[0].occurred_at, 'window_end': alerts[-1].occurred_at,
        'matched': matched, 'matched_at': matched_at, 'evidence': evidence,
    })
    if is_new or {a.pk for a in correlation.alerts.all()} != {a.pk for a in alerts}:
        correlation.alerts.set(alerts)
        changed = True
    score, level, types, basis = compute_risk([a.rule_type for a in alerts], matched)
    risk = RiskResult.objects.filter(correlation=correlation).first() or RiskResult(correlation=correlation)
    changed |= _save(risk, {
        'source_ip': ip, 'score': score, 'level': level, 'rule_types': types,
        'correlation_applied': matched, 'score_basis': basis,
    })
    counts['created' if is_new else 'updated' if changed else 'unchanged'] += 1
    if matched and score >= INCIDENT_MIN_SCORE and not Incident.objects.filter(correlation=correlation).exists():
        incident = Incident.objects.create(
            correlation=correlation, risk_result=risk, source_ip=ip, occurred_at=matched_at,
            risk_score=score, risk_level=level,
            creation_reason=(f'CorrelationResult #{correlation.pk} matched ({CORRELATION_TYPE}, same source_ip '
                             f'within 10 minutes) and risk {score} >= {INCIDENT_MIN_SCORE} ({level})'),
        )
        incident.alerts.set(alerts)
        counts['incidents'] += 1
    return correlation.pk


@transaction.atomic
def run_correlation():
    """Re-judge every source_ip. Returns counts of correlation scopes and new Incidents."""
    counts = {'created': 0, 'updated': 0, 'unchanged': 0, 'removed': 0, 'incidents': 0}
    by_ip = {}
    for alert in Alert.objects.order_by('occurred_at', 'id'):
        by_ip.setdefault(alert.source_ip, []).append(alert)
    kept = {_judge(ip, ssh, nginx, counts) for ip, alerts in by_ip.items() for ssh, nginx in build_scopes(alerts)}
    # Scopes can shift when earlier alerts arrive later; drop stale judgments no Incident relies on.
    stale = CorrelationResult.objects.exclude(pk__in=kept).filter(incident__isnull=True)
    counts['removed'] = stale.count()
    stale.delete()
    return counts
