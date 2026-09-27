import React from 'react';
import { EXECUTION, formatTime, go, ruleLabel, useApi, verificationLabel } from '../api';
import Status, { RiskBadge, SourceBadge } from './Status';

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

// Same retry/loading/error handling as other screens, applied to one field of /api/dashboard/.
function part(state, key) {
  return { ...state, data: state.data ? state.data[key] : null };
}

function SourceStatusTable({ rows }) {
  return (
    <table className="table">
      <thead><tr><th>로그</th><th>마지막 수신 (수집기 기준)</th><th>최근 수신 오류</th><th>전달 이상</th></tr></thead>
      <tbody>
        {rows.map((s) => (
          <tr key={s.source_type}>
            <td><SourceBadge type={s.source_type} /></td>
            {s.recorded ? (
              <>
                <td className="mono">{formatTime(s.last_received_at)}</td>
                <td className="wrap small">{s.last_error || '없음'}</td>
                <td>{s.delivery_anomaly ? <strong>전달 이상 표시</strong> : '이상 판정 없음'}</td>
              </>
            ) : (
              <td colSpan={3} className="muted">수신 기록 없음 (실장비 로그 수신 전)</td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Dashboard() {
  const dashboard = useApi('/api/dashboard/');
  const counts = dashboard.data?.counts ?? {};

  return (
    <>
      <section className="kpis" aria-label="집계">
        <Count label="보안 이벤트" state={dashboard} value={counts.events}
          detail={`Nginx ${counts.nginx_events} · SSH ${counts.ssh_events}`} />
        <Count label="경보 (Alert)" state={dashboard} value={counts.alerts} />
        <Count label="보안 사고 (Incident)" state={dashboard} value={counts.incidents} />
        <Count label="High 보안 사고" state={dashboard} value={counts.high_incidents} />
      </section>

      <section className="panel">
        <div className="panel-head"><h2>로그 수신 상태</h2></div>
        <p className="notice">
          <strong>TCP 5514 수집기 구현 및 로컬 소켓 검증 완료 / 실제 피해 서버 rsyslog 수신 검증 대기</strong><br />
          무수신(전달 이상) 자동 판정은 아직 없어 &quot;이상 판정 없음&quot;은 정상 수신을 뜻하지 않습니다.
        </p>
        <Status state={part(dashboard, 'source_status')}>
          <SourceStatusTable rows={dashboard.data?.source_status ?? []} />
        </Status>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>최근 보안 사고</h2>
          <a href="#/incidents">C 화면에서 보기</a>
        </div>
        <Status state={part(dashboard, 'recent_incidents')} empty="생성된 보안 사고 없음">
          <table className="table clickable">
            <thead>
              <tr><th>ID</th><th>발생 시각</th><th>출발지 IP</th><th>위험도</th><th>연결 경보</th><th>생성 근거</th></tr>
            </thead>
            <tbody>
              {(dashboard.data?.recent_incidents ?? []).map((i) => (
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
          <Status state={part(dashboard, 'recent_alerts')} empty="생성된 경보 없음">
            <table className="table clickable">
              <thead><tr><th>ID</th><th>발생 시각</th><th>탐지 규칙</th><th>출발지 IP</th></tr></thead>
              <tbody>
                {(dashboard.data?.recent_alerts ?? []).map((a) => (
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
          <Status state={part(dashboard, 'recent_events')} empty="저장된 이벤트 없음">
            <table className="table clickable">
              <thead><tr><th>ID</th><th>발생 시각</th><th>로그</th><th>출발지 IP</th><th>행동 / 결과</th></tr></thead>
              <tbody>
                {(dashboard.data?.recent_events ?? []).map((e) => (
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

      <section className="panel">
        <div className="panel-head">
          <h2>최근 자동 대응</h2>
          <a href="#/response">D 화면에서 보기</a>
        </div>
        <Status state={part(dashboard, 'recent_responses')} empty="아직 실제 자동 대응 실행 기록 없음">
          <table className="table clickable">
            <thead><tr><th>ID</th><th>대상 IP</th><th>발동 경보</th><th>실행 결과</th><th>실제 검증</th></tr></thead>
            <tbody>
              {(dashboard.data?.recent_responses ?? []).map((r) => (
                <tr key={r.id} onClick={() => go('response', r.id)}>
                  <td>#{r.id}</td>
                  <td className="mono">{r.target_ip ?? '-'}</td>
                  <td>#{r.triggering_alert_id}</td>
                  <td>{EXECUTION[r.execution_status]}</td>
                  <td>{verificationLabel(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Status>
      </section>
    </>
  );
}
