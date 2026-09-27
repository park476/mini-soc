import React, { useState } from 'react';
import { formatTime, go, ruleLabel, useApi } from '../api';
import Status, { SourceBadge } from './Status';

const FILTERS = [
  { key: 'all', label: '전체' },
  { key: 'nginx', label: 'Nginx' },
  { key: 'ssh', label: 'SSH' },
];

function EventDetail({ id, alerts }) {
  const detail = useApi(id ? `/api/events/${id}/` : null);
  if (!id) return <p className="state">목록에서 이벤트를 선택하세요.</p>;
  const linked = (alerts ?? []).filter((a) => a.related_event_ids.includes(id));
  return (
    <Status state={detail}>
      {detail.data && (
        <>
          <h3>이벤트 #{detail.data.id} <SourceBadge type={detail.data.source_type} /></h3>
          <dl className="fields">
            <dt>발생 시각</dt><dd className="mono">{formatTime(detail.data.event_time)}</dd>
            <dt>출발지 IP</dt><dd className="mono">{detail.data.source_ip ?? '-'}</dd>
            <dt>행동 (action)</dt><dd>{detail.data.action}</dd>
            <dt>결과 (result)</dt><dd>{detail.data.result}</dd>
            {detail.data.source_type === 'nginx' ? (
              <>
                <dt>요청 경로</dt><dd className="mono">{detail.data.request_path || '-'}</dd>
                <dt>HTTP 상태</dt><dd>{detail.data.http_status ?? '-'}</dd>
              </>
            ) : (
              <>
                <dt>SSH 근거</dt><dd className="mono wrap">{detail.data.ssh_evidence || '-'}</dd>
              </>
            )}
            <dt>저장 시각</dt><dd className="mono">{formatTime(detail.data.created_at)}</dd>
          </dl>
          <h4>원본 로그 (raw_log)</h4>
          <pre className="raw">{detail.data.raw_log}</pre>
          <h4>이 이벤트를 근거로 한 경보</h4>
          {linked.length === 0 ? <p className="state">연결된 경보 없음</p> : (
            <ul className="links">
              {linked.map((a) => (
                <li key={a.id}>
                  <button type="button" className="link-button" onClick={() => go('alerts', a.id)}>
                    경보 #{a.id} {ruleLabel(a.rule_type)}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
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
    <div className="split">
      <section className="panel">
        <div className="panel-head">
          <h2>보안 이벤트 목록</h2>
          <div className="segmented" role="group" aria-label="로그 종류">
            {FILTERS.map((f) => (
              <button key={f.key} type="button" className={filter === f.key ? 'active' : ''}
                onClick={() => setFilter(f.key)}>
                {f.label}
              </button>
            ))}
          </div>
        </div>
        <Status state={events} empty="저장된 이벤트 없음">
          <div className="scroll">
            <table className="table clickable">
              <thead>
                <tr>
                  <th>ID</th><th>로그</th><th>발생 시각</th><th>출발지 IP</th>
                  <th>행동</th><th>결과</th><th>요청 경로</th><th>HTTP</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className={e.id === selectedId ? 'selected' : ''} onClick={() => go('events', e.id)}>
                    <td>#{e.id}</td>
                    <td><SourceBadge type={e.source_type} /></td>
                    <td className="mono">{formatTime(e.event_time)}</td>
                    <td className="mono">{e.source_ip ?? '-'}</td>
                    <td>{e.action}</td>
                    <td>{e.result}</td>
                    <td className="mono">{e.request_path || '-'}</td>
                    <td>{e.http_status ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Status>
        <p className="note">정규화 실패 기록은 저장 모델만 있고 조회 API가 아직 없어 이 화면에 표시하지 않습니다.</p>
      </section>
      <section className="panel detail">
        <div className="panel-head"><h2>선택 이벤트 상세</h2></div>
        <EventDetail id={selectedId} alerts={alerts.data} />
      </section>
    </div>
  );
}
