import React from 'react';
import { byTime, formatGap, formatTime, go, RULE_ORDER, RULES, rowProps, ruleLabel, useApi } from '../api';
import Status, { ExecutionBadge, IdLinks, RiskBadge, SourceLabel, VerificationBadge } from './Status';

const INCIDENT_MIN_SCORE = 70;
const SHORT = { ssh_brute_force: 'SSH 무차별 대입', nginx_scan: 'Nginx 스캔', nginx_suspicious_path: '의심 경로' };

function ruleSource(ruleType) {
  return RULES[ruleType]?.source === 'SSH' ? 'ssh' : 'nginx';
}

// Emphasise the source IP inside stored evidence text without altering it.
function HighlightIp({ text, ip }) {
  if (!ip || !text.includes(ip)) return text;
  return text.split(ip).flatMap((part, index) => (index === 0 ? [part] : [<mark key={index} className="mono">{ip}</mark>, part]));
}

function AlertIndex({ state, selectedId }) {
  return (
    <Status state={state} empty="생성된 경보 없음">
      <ol className="index">
        {(state.data ?? []).map((a) => (
          <li key={a.id} {...rowProps(() => go('alerts', a.id), a.id === selectedId)}>
            <span className="index-title">{ruleLabel(a.rule_type)}</span>
            <span className="index-meta"><SourceLabel type={ruleSource(a.rule_type)} /> <span className="mono">{a.source_ip}</span></span>
            <span className="index-meta mono">{formatTime(a.occurred_at)} · 근거 {a.related_event_ids.length}건</span>
          </li>
        ))}
      </ol>
    </Status>
  );
}

function IncidentIndex({ state, selectedId }) {
  return (
    <Status state={state} empty="생성된 보안 사고 없음">
      <ol className="index">
        {(state.data ?? []).map((i) => (
          <li key={i.id} {...rowProps(() => go('incidents', i.id), i.id === selectedId)}>
            <span className="index-title">사고 {String(i.id).padStart(2, '0')} <span className="mono">{i.source_ip}</span></span>
            <span className="index-meta"><RiskBadge level={i.risk_level} score={i.risk_score} /> 경보 {i.alert_ids.length}건</span>
            <span className="index-meta mono">{formatTime(i.occurred_at)}</span>
          </li>
        ))}
      </ol>
    </Status>
  );
}

function AlertJudgement({ id, incidents }) {
  const detail = useApi(id ? `/api/alerts/${id}/` : null);
  const responses = useApi(id ? '/api/responses/' : null);
  if (!id) return <div className="state">왼쪽 목록에서 경보를 선택하세요.</div>;
  const linked = (incidents ?? []).filter((i) => i.alert_ids.includes(id));
  const response = (responses.data ?? []).find((r) => r.triggering_alert_id === id);
  const a = detail.data;
  return (
    <Status state={detail}>
      {a && (
        <article className="paper judgement">
          <header className="doc-head">
            <div>
              <span className="kicker">경보 #{a.id} · 탐지 판단</span>
              <h2 className="doc-title">{ruleLabel(a.rule_type)}</h2>
            </div>
            <div className="doc-head-side">
              <span className="mono big-meta">{a.source_ip}</span>
              <span className="mono">{formatTime(a.occurred_at)}</span>
            </div>
          </header>

          <ol className="reasoning">
            <li>
              <span className="step-name">왜 발생했나</span>
              <div>
                <p className="statement"><HighlightIp text={a.evidence} ip={a.source_ip} /></p>
                <p className="tz-note">근거 문장 내 시각은 저장된 원문(UTC) 표기이며, 화면 시각은 KST 기준입니다.</p>
              </div>
            </li>
            <li>
              <span className="step-name">규칙 논리 <span className="mono">{a.rule_type}</span></span>
              <p className="rule-chain">
                {a.rule_condition.split(', ').map((part, index) => (
                  <React.Fragment key={part}>
                    {index > 0 && <span className="rule-and">AND</span>}
                    <span className="mono">{part}</span>
                  </React.Fragment>
                ))}
              </p>
            </li>
            <li>
              <span className="step-name">근거 이벤트<span className="step-count">{a.related_event_ids.length}<small>건</small></span></span>
              <div>
                <ol className="evidence-strip" aria-label="근거 이벤트 ID">
                  {a.related_event_ids.map((eventId) => (
                    <li key={eventId} className={eventId === a.trigger_event ? 'is-trigger' : ''}>
                      <button type="button" onClick={() => go('events', eventId)}>
                        <span className="tick" aria-hidden="true" />
                        <span className="mono">#{eventId}</span>
                        {eventId === a.trigger_event && <span className="trigger-label">조건 완성</span>}
                      </button>
                    </li>
                  ))}
                </ol>
                <p className="sub">각 ID를 선택하면 B 화면에서 원본 로그를 봅니다</p>
              </div>
            </li>
            <li>
              <span className="step-name">다음 단계</span>
              <div className="next-steps">
                <p>
                  <span className="next-label">보안 사고</span>
                  {linked.length === 0 ? <span className="muted">없음 — 경보 단독은 보안 사고가 아님</span>
                    : <IdLinks ids={linked.map((i) => i.id)} screen="incidents" prefix="사고 #" />}
                </p>
                {a.rule_type === 'ssh_brute_force' && (
                  <p>
                    <span className="next-label">자동 대응</span>
                    {response ? (
                      <span className="inline-set">
                        <IdLinks ids={[response.id]} screen="response" prefix="대응 #" />
                        <ExecutionBadge status={response.execution_status} />
                        <VerificationBadge record={response} />
                      </span>
                    ) : <span className="muted">{responses.error ? '대응 기록 조회 오류' : '대응 기록 없음'}</span>}
                  </p>
                )}
              </div>
            </li>
          </ol>
        </article>
      )}
    </Status>
  );
}

function RiskVerdict({ risk }) {
  const basis = risk.score_basis ?? {};
  const ruleScores = basis.rule_scores ?? {};
  const rules = RULE_ORDER.filter((r) => r in ruleScores);
  const bonus = basis.correlation_bonus ?? 0;
  const capped = basis.uncapped > basis.cap;
  const level = String(risk.level).toLowerCase();
  return (
    <div className="calc">
      <div className="calc-terms">
        {rules.map((r, index) => (
          <React.Fragment key={r}>
            {index > 0 && <span className="calc-op">+</span>}
            <span className="calc-term"><b>{ruleScores[r]}</b><small>{SHORT[r]}</small></span>
          </React.Fragment>
        ))}
        <span className="calc-op">+</span>
        <span className="calc-term calc-corr"><b>{bonus}</b><small>상관분석 {risk.correlation_applied ? '성립' : '불성립'}</small></span>
        <span className="calc-op">=</span>
        <span className={`calc-term calc-raw${capped ? ' is-capped' : ''}`}><b>{basis.uncapped}</b><small>합계</small></span>
      </div>
      <div className={`calc-final verdict-${level}`}>
        <span className="calc-cap">{capped ? `상한 ${basis.cap}점 적용` : `상한 ${basis.cap}점 미만`}</span>
        <span className="calc-score">{risk.score}</span>
        <span className="calc-level">{String(risk.level).toUpperCase()}</span>
      </div>
      <p className="note calc-note">탐지 종류별 점수는 반복돼도 1회만 반영 · 등급 기준 Low 0–39 / Medium 40–69 / High 70–100 · 값은 저장된 score_basis</p>
    </div>
  );
}

function IncidentDocument({ id }) {
  const detail = useApi(id ? `/api/incidents/${id}/` : null);
  if (!id) return <div className="state">왼쪽 목록에서 보안 사고를 선택하세요.</div>;
  const i = detail.data;
  if (!i) return <Status state={detail} />;
  const c = i.correlation;
  const risk = i.risk_result;
  const alerts = [...i.alerts].sort(byTime('occurred_at'));
  const highEnough = i.risk_score >= INCIDENT_MIN_SCORE;
  const level = String(i.risk_level).toLowerCase();
  // Place the correlation junction after the alert that completed the pair (stored matched_at).
  const junctionAfter = alerts.findIndex((a) => a.occurred_at === c.matched_at);
  return (
    <article className="paper incident">
      <header className="doc-head">
        <div>
          <span className="kicker">보안 사고 {String(i.id).padStart(2, '0')} · 사건 분석</span>
          <h2 className="incident-ip mono">{i.source_ip}</h2>
          <p className="doc-meta">
            상관분석 성립 <span className="mono">{formatTime(i.occurred_at)}</span>
            <span className="dot-sep">·</span>기록 <span className="mono">{formatTime(i.created_at)}</span>
          </p>
          <p className="conditions">
            생성 조건 <span className={c.matched ? 'tone-success' : 'tone-danger'}>상관분석 {c.matched ? '성립' : '불성립'}</span>
            <span className="dot-sep">+</span>
            <span className={highEnough ? 'tone-success' : 'tone-danger'}>위험도 {i.risk_score} {highEnough ? '≥' : '<'} {INCIDENT_MIN_SCORE}</span>
          </p>
        </div>
        <div className={`verdict verdict-${level}`}>
          <span className="verdict-score">{i.risk_score}</span>
          <span className="verdict-level">{String(i.risk_level).toUpperCase()}</span>
        </div>
      </header>

      <div className="story">
        <section className="spine-col">
          <h3 className="label">공격 흐름 · 경보 {alerts.length}건</h3>
          <ol className="spine">
            {alerts.map((a, index) => (
              <React.Fragment key={a.id}>
                {index > 0 && <li className="spine-gap mono">{formatGap(alerts[index - 1].occurred_at, a.occurred_at)}</li>}
                <li className="spine-entry">
                  <button type="button" onClick={() => go('alerts', a.id)}>
                    <span className="spine-time mono">{formatTime(a.occurred_at).slice(11)}</span>
                    <span className="spine-text">
                      <span className="spine-rule">{ruleLabel(a.rule_type)}</span>
                      <span className="spine-ref"><SourceLabel type={ruleSource(a.rule_type)} /> 경보 #{a.id}</span>
                      <span className="spine-evidence"><HighlightIp text={a.evidence} ip={i.source_ip} /></span>
                    </span>
                  </button>
                </li>
                {index === junctionAfter && (
                  <li className="spine-junction">
                    <span className="mono">{formatTime(c.matched_at).slice(11)}</span>
                    <strong>상관분석 성립</strong>
                    <span>SSH 무차별 대입과 Nginx 경보가 동일 IP · 10분 이내</span>
                  </li>
                )}
              </React.Fragment>
            ))}
          </ol>
        </section>

        <aside className="margin">
          <h3 className="label">상관분석 근거</h3>
          <p className="margin-rule">
            동일 출발지 IP에서 SSH 무차별 대입 + (Nginx 스캔 또는 의심 경로 접근)이 <strong>10분 이내</strong>
          </p>
          <dl className="margin-facts">
            <div><dt>판단 범위</dt><dd className="mono">{formatTime(c.window_start).slice(11)} – {formatTime(c.window_end).slice(11)}</dd></div>
            <div><dt>성립 시각</dt><dd className="mono">{formatTime(c.matched_at)}</dd></div>
            <div><dt>연결 경보</dt><dd><IdLinks ids={c.alert_ids} screen="alerts" /></dd></div>
            <div><dt>유형</dt><dd className="mono">{c.correlation_type}</dd></div>
          </dl>
          <ul className="margin-evidence mono">
            {c.evidence.split('; ').map((line) => <li key={line}><HighlightIp text={line} ip={i.source_ip} /></li>)}
          </ul>
          <p className="tz-note">근거 문장 내 시각은 저장된 원문(UTC) 표기이며, 화면 시각은 KST 기준입니다.</p>
          <p className="margin-reason mono">{i.creation_reason}</p>
        </aside>
      </div>

      <section className="verdict-section">
        <h3 className="label">판정 · 위험도 산정</h3>
        <RiskVerdict risk={risk} />
        {risk.score !== i.risk_score && (
          <p className="note">보안 사고에는 생성 당시 점수 {i.risk_score}가 저장되어 있고, 현재 재판단 점수는 {risk.score}입니다.</p>
        )}
      </section>
    </article>
  );
}

export default function AlertsIncidents({ mode, selectedId }) {
  const alerts = useApi('/api/alerts/');
  const incidents = useApi('/api/incidents/');
  const isIncident = mode === 'incidents';

  return (
    <div className="casefile">
      <nav className="case-index" aria-label="경보와 보안 사고 목록">
        <h1 className="screen-title">경보 · 보안 사고</h1>
        <div className="filter" role="group" aria-label="목록 전환">
          <button type="button" className={isIncident ? '' : 'active'} aria-pressed={!isIncident} onClick={() => go('alerts')}>
            경보 {alerts.data ? alerts.data.length : ''}
          </button>
          <button type="button" className={isIncident ? 'active' : ''} aria-pressed={isIncident} onClick={() => go('incidents')}>
            보안 사고 {incidents.data ? incidents.data.length : ''}
          </button>
        </div>
        {isIncident
          ? <IncidentIndex state={incidents} selectedId={selectedId} />
          : <AlertIndex state={alerts} selectedId={selectedId} />}
        <p className="note">경보는 단일 탐지 규칙 결과이고, 보안 사고는 상관분석 성립 + 위험도 High일 때만 생성됩니다.</p>
      </nav>
      <div className="case-body">
        {isIncident
          ? <IncidentDocument id={selectedId} />
          : <AlertJudgement id={selectedId} incidents={incidents.data} />}
      </div>
    </div>
  );
}
