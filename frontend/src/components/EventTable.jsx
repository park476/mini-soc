import React, { useState } from 'react';
import { formatTime, go, rowProps, ruleLabel, useApi } from '../api';
import Status, { ResultBadge, ResultText, SourceLabel } from './Status';

const FILTERS = [
  { key: 'all', label: '전체' },
  { key: 'nginx', label: 'Nginx' },
  { key: 'ssh', label: 'SSH' },
];

function Dossier({ id, alerts }) {
  const detail = useApi(id ? `/api/events/${id}/` : null);
  if (!id) return <div className="state">왼쪽 기록에서 이벤트를 선택하면 원본 로그와 연결된 경보를 봅니다.</div>;
  const linked = (alerts ?? []).filter((a) => a.related_event_ids.includes(id));
  const e = detail.data;
  return (
    <Status state={detail}>
      {e && (
        <article className="dossier">
          <span className="kicker">보안 이벤트 {e.id} · <SourceLabel type={e.source_type} /></span>
          <h2 className="dossier-ip mono">{e.source_ip ?? '-'}</h2>
          <p className="dossier-time mono">{formatTime(e.event_time)}</p>

          <div className="facts">
            {e.source_type === 'nginx' ? (
              <div className="fact fact-wide">
                <span className="fact-label">요청</span>
                <span className="fact-value"><span className="method">{e.action}</span> <span className="mono">{e.request_path || '-'}</span></span>
              </div>
            ) : (
              <div className="fact fact-wide">
                <span className="fact-label">SSH 인증 기록</span>
                <span className="fact-value mono small">{e.ssh_evidence || '-'}</span>
              </div>
            )}
            <div className="fact">
              <span className="fact-label">결과</span>
              <span className="fact-value">
                {e.http_status != null && <span className="mono">{e.http_status} </span>}<ResultBadge result={e.result} />
              </span>
            </div>
            <div className="fact">
              <span className="fact-label">행동</span>
              <span className="fact-value">{e.action}</span>
            </div>
            <div className="fact fact-wide">
              <span className="fact-label">이 이벤트를 근거로 한 경보</span>
              <span className="fact-value">
                {linked.length === 0 ? <span className="muted">연결된 경보 없음</span> : linked.map((a) => (
                  <button key={a.id} type="button" className="link" onClick={() => go('alerts', a.id)}>
                    경보 #{a.id} {ruleLabel(a.rule_type)} →
                  </button>
                ))}
              </span>
            </div>
          </div>

          <div className="raw-block">
            <span className="raw-label">RAW LOG</span>
            <pre className="raw">{e.raw_log}</pre>
            <span className="raw-meta">관제 서버 저장 <span className="mono">{formatTime(e.created_at)}</span></span>
          </div>
        </article>
      )}
    </Status>
  );
}

export default function EventTable({ selectedId }) {
  const events = useApi('/api/events/');
  const alerts = useApi('/api/alerts/');
  const [filter, setFilter] = useState('all');
  const rows = (events.data ?? []).filter((e) => filter === 'all' || e.source_type === filter);

  return (
    <div className="investigate">
      <section className="stream">
        <header className="stream-head">
          <div>
            <h1 className="screen-title">보안 이벤트</h1>
            <p className="screen-note">Nginx · SSH 원본 로그를 정규화한 기록 {events.data ? `${rows.length}건` : ''}</p>
          </div>
          <div className="filter" role="group" aria-label="로그 종류">
            {FILTERS.map((f) => (
              <button key={f.key} type="button" className={filter === f.key ? 'active' : ''}
                aria-pressed={filter === f.key} onClick={() => setFilter(f.key)}>
                {f.label}
              </button>
            ))}
          </div>
        </header>
        <Status state={events} empty="저장된 이벤트 없음">
          <div className="stream-scroll">
            <table className="log">
              <thead>
                <tr><th>발생 시각</th><th>로그</th><th>출발지 IP</th><th>요청 · 행동</th><th className="num">결과</th><th className="num">ID</th></tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} {...rowProps(() => go('events', e.id), e.id === selectedId)}>
                    <td className="mono">{formatTime(e.event_time)}</td>
                    <td><SourceLabel type={e.source_type} /></td>
                    <td className="mono">{e.source_ip ?? '-'}</td>
                    <td className="clip">
                      {e.source_type === 'nginx'
                        ? <><span className="method">{e.action}</span> <span className="mono">{e.request_path || '-'}</span></>
                        : e.action}
                    </td>
                    <td className="num">
                      {e.http_status != null && <span className="mono muted">{e.http_status} </span>}<ResultText result={e.result} />
                    </td>
                    <td className="num muted">{e.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Status>
        <p className="note">
          정규화 실패는 TCP 수집기가 원본과 실패 이유를 NormalizationFailure로 저장합니다.
          전용 조회 API 계약이 확정되지 않아 이 화면에는 목록을 표시하지 않습니다.
        </p>
      </section>
      <aside className="inspector">
        <Dossier id={selectedId} alerts={alerts.data} />
      </aside>
    </div>
  );
}
