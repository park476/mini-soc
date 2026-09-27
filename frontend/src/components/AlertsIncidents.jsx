import React from 'react';
import { byTime, formatTime, go, RULE_ORDER, ruleLabel, useApi } from '../api';
import Status, { RiskBadge } from './Status';

const INCIDENT_MIN_SCORE = 70;

function AlertList({ state, selectedId }) {
  return (
    <Status state={state} empty="생성된 경보 없음">
      <table className="table clickable">
        <thead><tr><th>ID</th><th>탐지 규칙</th><th>출발지 IP</th><th>발생 시각</th><th>근거 이벤트</th></tr></thead>
        <tbody>
          {(state.data ?? []).map((a) => (
            <tr key={a.id} className={a.id === selectedId ? 'selected' : ''} onClick={() => go('alerts', a.id)}>
              <td>#{a.id}</td>
              <td>{ruleLabel(a.rule_type)}<div className="code">{a.rule_type}</div></td>
              <td className="mono">{a.source_ip}</td>
              <td className="mono">{formatTime(a.occurred_at)}</td>
              <td>{a.related_event_ids.length}건</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Status>
  );
}

function IncidentList({ state, selectedId }) {
  return (
    <Status state={state} empty="생성된 보안 사고 없음">
      <table className="table clickable">
        <thead><tr><th>ID</th><th>출발지 IP</th><th>발생 시각</th><th>위험도</th><th>연결 경보</th></tr></thead>
        <tbody>
          {(state.data ?? []).map((i) => (
            <tr key={i.id} className={i.id === selectedId ? 'selected' : ''} onClick={() => go('incidents', i.id)}>
              <td>#{i.id}</td>
              <td className="mono">{i.source_ip}</td>
              <td className="mono">{formatTime(i.occurred_at)}</td>
              <td><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
              <td>{i.alert_ids.map((id) => `#${id}`).join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Status>
  );
}

function EventLinks({ ids }) {
  return (
    <span className="chips">
      {ids.map((id) => (
        <button key={id} type="button" className="chip" onClick={() => go('events', id)}>#{id}</button>
      ))}
    </span>
  );
}

function AlertDetail({ id, incidents }) {
  const detail = useApi(id ? `/api/alerts/${id}/` : null);
  if (!id) return <p className="state">목록에서 경보를 선택하세요.</p>;
  const linked = (incidents ?? []).filter((i) => i.alert_ids.includes(id));
  const a = detail.data;
  return (
    <Status state={detail}>
      {a && (
        <>
          <h3>경보 #{a.id} · {ruleLabel(a.rule_type)}</h3>
          <dl className="fields">
            <dt>탐지 규칙</dt><dd className="mono">{a.rule_type}</dd>
            <dt>적용 조건</dt><dd className="mono wrap">{a.rule_condition}</dd>
            <dt>출발지 IP</dt><dd className="mono">{a.source_ip}</dd>
            <dt>발생 시각</dt><dd className="mono">{formatTime(a.occurred_at)}</dd>
            <dt>탐지 근거</dt><dd className="wrap">{a.evidence}</dd>
            <dt>근거 이벤트</dt><dd><EventLinks ids={a.related_event_ids} /> <span className="muted">(선택 시 B 화면 원본 로그)</span></dd>
            <dt>조건 완성 이벤트</dt><dd><EventLinks ids={[a.trigger_event]} /></dd>
            <dt>연결 보안 사고</dt>
            <dd>
              {linked.length === 0 ? <span className="muted">없음 (경보 단독은 보안 사고가 아님)</span> : linked.map((i) => (
                <button key={i.id} type="button" className="chip" onClick={() => go('incidents', i.id)}>
                  Incident #{i.id}
                </button>
              ))}
            </dd>
          </dl>
        </>
      )}
    </Status>
  );
}

function RiskBreakdown({ risk }) {
  const basis = risk.score_basis ?? {};
  const ruleScores = basis.rule_scores ?? {};
  const rules = RULE_ORDER.filter((r) => r in ruleScores);
  const parts = [...rules.map((r) => ruleScores[r]), ...(basis.correlation_bonus ? [basis.correlation_bonus] : [])];
  const capped = basis.uncapped > basis.cap;
  return (
    <>
      <table className="table score">
        <thead><tr><th>반영 항목</th><th className="num">점수</th></tr></thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r}><td>{ruleLabel(r)} <span className="code">{r}</span></td><td className="num">+{ruleScores[r]}</td></tr>
          ))}
          <tr>
            <td>상관분석 가산 {risk.correlation_applied ? '(성립)' : '(불성립)'}</td>
            <td className="num">+{basis.correlation_bonus ?? 0}</td>
          </tr>
          <tr className="subtotal"><td>합계 (상한 적용 전)</td><td className="num">{basis.uncapped}</td></tr>
          <tr className="subtotal">
            <td>상한 {basis.cap}점 {capped ? '적용' : '미적용'}</td>
            <td className="num">{Math.min(basis.uncapped, basis.cap)}</td>
          </tr>
          <tr className="total"><td>최종 위험도</td><td className="num"><RiskBadge level={risk.level} score={risk.score} /></td></tr>
        </tbody>
      </table>
      <p className="formula">
        {parts.join(' + ')} = {basis.uncapped}
        {capped && <> → 상한 {basis.cap} 적용</>} → <strong>{risk.score}</strong> ({risk.level})
      </p>
      <p className="note">
        같은 탐지 종류는 반복돼도 1회만 반영 · 등급 기준: Low 0–39 / Medium 40–69 / High 70–100
      </p>
    </>
  );
}

function IncidentDetail({ id }) {
  const detail = useApi(id ? `/api/incidents/${id}/` : null);
  if (!id) return <p className="state">목록에서 보안 사고를 선택하세요.</p>;
  const i = detail.data;
  if (!i) return <Status state={detail} />;
  const c = i.correlation;
  const risk = i.risk_result;
  const alerts = [...i.alerts].sort(byTime('occurred_at'));
  return (
    <>
      <h3>보안 사고 #{i.id} · 출발지 <span className="mono">{i.source_ip}</span> <RiskBadge level={i.risk_level} score={i.risk_score} /></h3>
      <dl className="fields">
        <dt>발생 시각</dt><dd className="mono">{formatTime(i.occurred_at)} <span className="muted">(상관분석 성립 시각)</span></dd>
        <dt>기록 시각</dt><dd className="mono">{formatTime(i.created_at)}</dd>
      </dl>

      <h4>1. 생성 근거</h4>
      <ul className="checks">
        <li className={c.matched ? 'ok' : 'no'}>상관분석 성립: {c.matched ? '예' : '아니오'} (CorrelationResult #{c.id})</li>
        <li className={i.risk_score >= INCIDENT_MIN_SCORE ? 'ok' : 'no'}>
          위험도 {i.risk_score} ≥ {INCIDENT_MIN_SCORE} (High): {i.risk_score >= INCIDENT_MIN_SCORE ? '예' : '아니오'}
        </li>
      </ul>
      <p className="mono wrap small">{i.creation_reason}</p>

      <h4>2. 연결된 경보 (시간순)</h4>
      <table className="table clickable">
        <thead><tr><th>ID</th><th>발생 시각</th><th>탐지 규칙</th><th>근거</th></tr></thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id} onClick={() => go('alerts', a.id)}>
              <td>#{a.id}</td>
              <td className="mono">{formatTime(a.occurred_at)}</td>
              <td>{ruleLabel(a.rule_type)}</td>
              <td className="wrap small">{a.evidence}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h4>3. 상관분석 근거</h4>
      <dl className="fields">
        <dt>규칙</dt><dd>동일 출발지 IP에서 SSH 무차별 대입 + (Nginx 스캔 또는 의심 경로 접근)이 10분 이내 <span className="code">{c.correlation_type}</span></dd>
        <dt>판단 범위</dt><dd className="mono">{formatTime(c.window_start)} ~ {formatTime(c.window_end)}</dd>
        <dt>성립 시각</dt><dd className="mono">{formatTime(c.matched_at)}</dd>
        <dt>연결 경보</dt><dd>{c.alert_ids.map((a) => `#${a}`).join(', ')}</dd>
        <dt>근거</dt>
        <dd>
          <ul className="evidence">
            {c.evidence.split('; ').map((line) => <li key={line} className="wrap">{line}</li>)}
          </ul>
        </dd>
      </dl>

      <h4>4. 위험도 산정</h4>
      <RiskBreakdown risk={risk} />
      {risk.score !== i.risk_score && (
        <p className="note">보안 사고에는 생성 당시 점수 {i.risk_score}가 저장되어 있고, 현재 재판단 점수는 {risk.score}입니다.</p>
      )}
    </>
  );
}

export default function AlertsIncidents({ mode, selectedId }) {
  const alerts = useApi('/api/alerts/');
  const incidents = useApi('/api/incidents/');
  const isIncident = mode === 'incidents';

  return (
    <div className="split">
      <section className="panel">
        <div className="panel-head">
          <div className="segmented" role="group" aria-label="목록 전환">
            <button type="button" className={isIncident ? '' : 'active'} onClick={() => go('alerts')}>
              경보 (Alert) {alerts.data ? alerts.data.length : ''}
            </button>
            <button type="button" className={isIncident ? 'active' : ''} onClick={() => go('incidents')}>
              보안 사고 (Incident) {incidents.data ? incidents.data.length : ''}
            </button>
          </div>
        </div>
        {isIncident
          ? <IncidentList state={incidents} selectedId={selectedId} />
          : <AlertList state={alerts} selectedId={selectedId} />}
        <p className="note">경보는 단일 탐지 규칙 결과이고, 보안 사고는 상관분석 성립 + 위험도 High일 때만 생성됩니다.</p>
      </section>
      <section className="panel detail">
        <div className="panel-head"><h2>{isIncident ? '보안 사고 상세' : '경보 상세'}</h2></div>
        {isIncident
          ? <IncidentDetail id={selectedId} />
          : <AlertDetail id={selectedId} incidents={incidents.data} />}
      </section>
    </div>
  );
}
