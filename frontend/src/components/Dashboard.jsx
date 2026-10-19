import React from 'react';
import {
  byTime, EXECUTION, formatGap, formatTime, go, RULE_ORDER, RULES, rowProps, ruleLabel, useApi, verificationLabel,
} from '../api';
import Status, { SourceLabel } from './Status';

const SHORT = { ssh_brute_force: 'SSH 무차별 대입', nginx_scan: 'Nginx 스캔', nginx_suspicious_path: '의심 경로' };

// Same retry/loading/error handling as other screens, applied to one field of /api/dashboard/.
function part(state, key) {
  return { ...state, data: state.data ? state.data[key] : null };
}

function Briefing({ incident }) {
  const alerts = [...(incident.alerts ?? [])].sort(byTime('occurred_at'));
  const c = incident.correlation;
  const basis = incident.risk_result?.score_basis ?? {};
  const ruleScores = basis.rule_scores ?? {};
  const level = String(incident.risk_level).toLowerCase();
  return (
    <article className="briefing">
      <div className="briefing-id">
        <div>
          <span className="kicker">현재 보안 상태 · INCIDENT {String(incident.id).padStart(2, '0')}</span>
          <h1 className="briefing-ip mono">{incident.source_ip}</h1>
          {c && (
            <p className="briefing-meta">
              상관분석 성립 <span className="mono">{formatTime(c.matched_at).slice(11)}</span>
              <span className="dot-sep">·</span>판단 범위 <span className="mono">{formatTime(c.window_start).slice(11)} – {formatTime(c.window_end).slice(11)}</span>
            </p>
          )}
        </div>
        <div className={`verdict verdict-${level}`}>
          <span className="verdict-score">{incident.risk_score}</span>
          <span className="verdict-level">{String(incident.risk_level).toUpperCase()}</span>
          <span className="verdict-caption">위험도 / 100</span>
        </div>
      </div>

      <ol className="chain" aria-label="공격 흐름">
        {alerts.map((a, index) => (
          <li key={a.id}>
            {index > 0 && <span className="chain-gap mono">{formatGap(alerts[index - 1].occurred_at, a.occurred_at)}</span>}
            <span className="chain-time mono">{formatTime(a.occurred_at).slice(11)}</span>
            <span className="chain-node" aria-hidden="true" />
            <span className="chain-rule">{ruleLabel(a.rule_type)}</span>
            <span className="chain-ref">{RULES[a.rule_type]?.source} 로그 · 경보 #{a.id}</span>
          </li>
        ))}
      </ol>

      {incident.risk_result && (
        <p className="briefing-why">
          <span className="why-label">왜 {incident.risk_result.score}인가</span>
          {RULE_ORDER.filter((r) => r in ruleScores).map((r) => (
            <span key={r} className="why-term"><b>{ruleScores[r]}</b> {SHORT[r]}</span>
          ))}
          {basis.correlation_bonus > 0 && <span className="why-term why-corr"><b>{basis.correlation_bonus}</b> 상관분석</span>}
          <span className="why-sum">= {basis.uncapped}{basis.uncapped > basis.cap && `, 상한 ${basis.cap}`}</span>
          <a className="link-strong" href={`#/incidents/${incident.id}`}>사건 분석 문서 →</a>
        </p>
      )}
    </article>
  );
}

// Mirrors backend events/correlation.py RULE_SCORES and risk_level(): a lone Alert's rule score, no correlation bonus.
const RULE_SCORE = { ssh_brute_force: 40, nginx_scan: 30, nginx_suspicious_path: 20 };
const levelOf = (score) => (score >= 70 ? 'High' : score >= 40 ? 'Medium' : 'Low');

// Latest detected attack. It is an Alert, not an Incident: no Incident exists for it.
function LatestAlert({ alert, incident }) {
  const score = RULE_SCORE[alert.rule_type];
  const level = score === undefined ? null : levelOf(score);
  return (
    <article className="briefing">
      <div className="briefing-id">
        <div>
          <span className="kicker">현재 보안 상태 · 최근 공격 탐지 · 경보 #{alert.id}</span>
          <h1 className="briefing-ip mono">{alert.source_ip}</h1>
          <p className="briefing-meta">
            탐지 시각 <span className="mono">{formatTime(alert.occurred_at)}</span>
            <span className="dot-sep">·</span>{ruleLabel(alert.rule_type)}
            <span className="dot-sep">·</span>{RULES[alert.rule_type]?.source} 로그
          </p>
        </div>
        {level && (
          <div className={`verdict verdict-${level.toLowerCase()}`}>
            <span className="verdict-score">{score}</span>
            <span className="verdict-level">{level.toUpperCase()}</span>
            <span className="verdict-caption">규칙 점수 / 100</span>
          </div>
        )}
      </div>
      {alert.evidence && <p className="briefing-meta mono">{alert.evidence}</p>}
      <p className="briefing-why">
        <span className="why-label">보안 사고 아님</span>
        <span className="why-term">단일 경보 · 상관분석 미성립 (사고는 상관분석 성립 + 위험도 70 이상일 때만 생성)</span>
        <a className="link-strong" href={`#/alerts/${alert.id}`}>경보 상세 →</a>
        {incident && (
          <a className="link-strong" href={`#/incidents/${incident.id}`}>
            최근 보안 사고 INCIDENT {String(incident.id).padStart(2, '0')} ({incident.source_ip}, {incident.risk_score}) →
          </a>
        )}
      </p>
    </article>
  );
}

// Colour for the latest stored response: success only when its effect verification succeeded.
function responseTone(record) {
  if (!record) return '';
  const verification = record.verification?.verification_status;
  if (verification === 'success') return 'success';
  if (verification === 'failed' || record.execution_status === 'failed') return 'danger';
  return 'warning';
}

// Event → Alert → Incident → Response as one vertical track of stored counts.
function Track({ state }) {
  const c = state.data?.counts ?? {};
  const latest = state.data?.recent_responses?.[0];
  const n = (value) => (state.loading && !state.data ? '…' : state.error ? '—' : value);
  const steps = [
    { label: '보안 이벤트', value: c.events, href: '#/events', sub: state.data ? `Nginx ${c.nginx_events} · SSH ${c.ssh_events}` : '' },
    { edge: '탐지 규칙 3종' },
    { label: '경보', value: c.alerts, href: '#/alerts' },
    { edge: '동일 IP 10분 상관분석 · 위험도 70 이상' },
    { label: '보안 사고', value: c.incidents, href: '#/incidents', danger: c.high_incidents > 0, sub: state.data ? `High ${c.high_incidents}` : '' },
    { edge: 'SSH 무차별 대입 경보가 발동 조건' },
    // Stored records only: the count and the latest record's result, not whether automatic response is enabled.
    { label: '자동 대응 기록', value: c.responses, href: '#/response', tone: responseTone(latest),
      sub: !state.data ? '' : latest ? `최근 기록: ${EXECUTION[latest.execution_status]} · ${verificationLabel(latest)}` : '대응 기록 없음' },
  ];
  return (
    <aside className="track" aria-label="관측에서 판단까지">
      <span className="kicker">관측 → 판단</span>
      <ol>
        {steps.map((s) => (s.edge ? (
          <li key={s.edge} className="track-edge">{s.edge}</li>
        ) : (
          <li key={s.label} className={`track-step${s.danger ? ' is-danger' : ''}`}>
            <a href={s.href}>
              <span className="track-value">{n(s.value)}</span>
              <span className="track-label">{s.label}</span>
              {s.sub && <span className={`track-sub${s.tone ? ` tone-${s.tone}` : ''}`}>{s.sub}</span>}
            </a>
          </li>
        )))}
      </ol>
    </aside>
  );
}

function CollectionPath({ state }) {
  const sources = state.data?.source_status ?? [];
  // Derived from stored receive records only; says nothing about whether delivery is healthy right now.
  const received = sources.filter((s) => s.recorded && s.last_received_at);
  const lastReceived = received.map((s) => s.last_received_at).sort().at(-1);
  return (
    <section className="column">
      <h2 className="column-title">수집 경로</h2>
      <dl className="lines">
        <div><dt>Collector <span className="mono">TCP 5514</span></dt><dd className="tone-success">구현 · 로컬 소켓 검증 완료</dd></div>
        <Status state={part(state, 'source_status')}>
          <div>
            <dt>피해 서버 로그 수신</dt>
            {received.length ? (
              <dd className="tone-success">
                수신 기록 있음 ({received.length}/{sources.length}종)
                <span className="sub">최근 <span className="mono">{formatTime(lastReceived)}</span></span>
              </dd>
            ) : <dd className="tone-warning">수신 기록 없음</dd>}
          </div>
          {sources.map((s) => (
            <div key={s.source_type}>
              <dt><SourceLabel type={s.source_type} /></dt>
              {s.recorded ? (
                <dd>
                  마지막 수신 <span className="mono">{formatTime(s.last_received_at)}</span>
                  <span className="sub">{s.delivery_anomaly ? '전달 이상 표시' : '이상 판정 없음'}</span>
                  {s.last_error && <span className="sub tone-danger">{s.last_error}</span>}
                </dd>
              ) : (
                <dd>수신 기록 없음</dd>
              )}
            </div>
          ))}
        </Status>
      </dl>
      <p className="note">무수신(전달 이상) 자동 판정은 아직 없어 &quot;이상 판정 없음&quot;은 정상 수신을 뜻하지 않습니다.</p>
    </section>
  );
}

export default function Dashboard() {
  const dashboard = useApi('/api/dashboard/', 5000);
  const incident = dashboard.data?.recent_incidents?.[0];
  const alert = dashboard.data?.recent_alerts?.[0];
  // Top shows whichever is newer: the latest Incident, or a later Alert that formed no Incident.
  const alertIsNewer = alert && (!incident || new Date(alert.occurred_at) > new Date(incident.occurred_at));

  return (
    <div className="dashboard">
      <section className="band">
        <div className="band-inner dash-top">
          {alertIsNewer ? <LatestAlert alert={alert} incident={incident} /> : (
            <Status state={part(dashboard, 'recent_incidents')} empty={(
              <div className="briefing briefing-none">
                <span className="kicker">현재 보안 상태</span>
                <p className="none-title">현재 보안 사고 없음</p>
                <p className="note">보안 사고는 상관분석 성립 + 위험도 70 이상일 때만 생성됩니다.</p>
              </div>
            )}>
              {incident && <Briefing incident={incident} />}
            </Status>
          )}
          <Track state={dashboard} />
        </div>
      </section>

      <div className="dash-bottom">
        <CollectionPath state={dashboard} />

        <section className="column">
          <h2 className="column-title">최근 보안 이벤트 <a className="more" href="#/events">전체 보기</a></h2>
          <Status state={part(dashboard, 'recent_events')} empty="저장된 이벤트 없음">
            <table className="list">
              <tbody>
                {(dashboard.data?.recent_events ?? []).map((e) => (
                  <tr key={e.id} {...rowProps(() => go('events', e.id))}>
                    <td className="mono">{formatTime(e.event_time)}</td>
                    <td><SourceLabel type={e.source_type} /></td>
                    <td className="mono">{e.source_ip ?? '-'}</td>
                    <td className="clip">
                      {e.action} {e.http_status ?? e.result}
                      {e.request_path && <span className="mono muted"> {e.request_path}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Status>
        </section>

        <section className="column">
          <h2 className="column-title">최근 경보 <a className="more" href="#/alerts">전체 보기</a></h2>
          <Status state={part(dashboard, 'recent_alerts')} empty="생성된 경보 없음">
            <table className="list">
              <tbody>
                {(dashboard.data?.recent_alerts ?? []).map((a) => (
                  <tr key={a.id} {...rowProps(() => go('alerts', a.id))}>
                    <td className="mono">{formatTime(a.occurred_at)}</td>
                    <td className="strong">{ruleLabel(a.rule_type)}</td>
                    <td className="mono">{a.source_ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Status>
        </section>
      </div>
    </div>
  );
}
