import React from 'react';
import { EXECUTION, formatTime, go, ruleLabel, useApi, verificationLabel } from '../api';
import Status, { RiskBadge, SourceBadge } from './Status';

const RECENT = 6;

function Count({ label, state, value, detail }) {
  let shown = value;
  if (state.loading && !state.data) shown = '…';
  else if (state.error) shown = '조회 오류';
  return (
    <div className="kpi">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{shown}</span>
      {detail && !state.error && state.data && <span className="kpi-detail">{detail}</span>}
    </div>
  );
}

export default function Dashboard() {
  const events = useApi('/api/events/');
  const alerts = useApi('/api/alerts/');
  const incidents = useApi('/api/incidents/');
  const responses = useApi('/api/responses/');

  const eventList = events.data ?? [];
  const alertList = alerts.data ?? [];
  const incidentList = incidents.data ?? [];
  const nginxCount = eventList.filter((e) => e.source_type === 'nginx').length;
  const highCount = incidentList.filter((i) => i.risk_level === 'High').length;

  return (
    <>
      <section className="kpis" aria-label="집계">
        <Count label="보안 이벤트" state={events} value={eventList.length}
          detail={`Nginx ${nginxCount} · SSH ${eventList.length - nginxCount}`} />
        <Count label="경보 (Alert)" state={alerts} value={alertList.length} />
        <Count label="보안 사고 (Incident)" state={incidents} value={incidentList.length} />
        <Count label="High 보안 사고" state={incidents} value={highCount} />
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>최근 보안 사고</h2>
          <a href="#/incidents">C 화면에서 보기</a>
        </div>
        <Status state={incidents} empty="생성된 보안 사고 없음">
          <table className="table clickable">
            <thead>
              <tr><th>ID</th><th>발생 시각</th><th>출발지 IP</th><th>위험도</th><th>연결 경보</th><th>생성 근거</th></tr>
            </thead>
            <tbody>
              {incidentList.slice(0, RECENT).map((i) => (
                <tr key={i.id} onClick={() => go('incidents', i.id)}>
                  <td>#{i.id}</td>
                  <td className="mono">{formatTime(i.occurred_at)}</td>
                  <td className="mono">{i.source_ip}</td>
                  <td><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
                  <td>{(i.alerts ?? []).map((a) => ruleLabel(a.rule_type)).join(', ')}</td>
                  <td className="wrap">{i.creation_reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Status>
      </section>

      <div className="columns">
        <section className="panel">
          <div className="panel-head">
            <h2>최근 경보</h2>
            <a href="#/alerts">C 화면에서 보기</a>
          </div>
          <Status state={alerts} empty="생성된 경보 없음">
            <table className="table clickable">
              <thead><tr><th>ID</th><th>발생 시각</th><th>탐지 규칙</th><th>출발지 IP</th></tr></thead>
              <tbody>
                {alertList.slice(0, RECENT).map((a) => (
                  <tr key={a.id} onClick={() => go('alerts', a.id)}>
                    <td>#{a.id}</td>
                    <td className="mono">{formatTime(a.occurred_at)}</td>
                    <td>{ruleLabel(a.rule_type)}</td>
                    <td className="mono">{a.source_ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Status>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>최근 보안 이벤트</h2>
            <a href="#/events">B 화면에서 보기</a>
          </div>
          <Status state={events} empty="저장된 이벤트 없음">
            <table className="table clickable">
              <thead><tr><th>ID</th><th>발생 시각</th><th>로그</th><th>출발지 IP</th><th>행동 / 결과</th></tr></thead>
              <tbody>
                {eventList.slice(0, RECENT).map((e) => (
                  <tr key={e.id} onClick={() => go('events', e.id)}>
                    <td>#{e.id}</td>
                    <td className="mono">{formatTime(e.event_time)}</td>
                    <td><SourceBadge type={e.source_type} /></td>
                    <td className="mono">{e.source_ip ?? '-'}</td>
                    <td>{e.action} / {e.http_status ?? e.result}{e.request_path && ` ${e.request_path}`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Status>
        </section>
      </div>

      <div className="columns">
        <section className="panel">
          <div className="panel-head"><h2>로그 수신 상태</h2></div>
          <p className="notice">
            <strong>조회 화면 미구현</strong> — 수신 상태 기록 모델은 있으나 조회 API와 실제 rsyslog/TCP 수집기(T2-B)는
            구현 예정입니다. 현재 이벤트는 통제된 샘플 로그를 import한 결과입니다.
          </p>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>최근 자동 대응</h2>
            <a href="#/response">D 화면에서 보기</a>
          </div>
          <Status state={responses} empty="아직 실제 자동 대응 실행 기록 없음">
            <table className="table clickable">
              <thead><tr><th>ID</th><th>대상 IP</th><th>실행 결과</th><th>실제 검증</th></tr></thead>
              <tbody>
                {(responses.data ?? []).slice(0, RECENT).map((r) => (
                  <tr key={r.id} onClick={() => go('response', r.id)}>
                    <td>#{r.id}</td>
                    <td className="mono">{r.target_ip ?? '-'}</td>
                    <td>{EXECUTION[r.execution_status]}</td>
                    <td>{verificationLabel(r)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Status>
        </section>
      </div>
    </>
  );
}
