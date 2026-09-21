import React, { useEffect, useState } from 'react';

export default function EventTable() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();

    async function loadEvents() {
      try {
        const response = await fetch('/api/events/', { signal: controller.signal });
        if (!response.ok) {
          throw new Error(`이벤트 조회에 실패했습니다. (HTTP ${response.status})`);
        }
        const data = await response.json();
        if (!Array.isArray(data)) {
          throw new Error('이벤트 응답 형식이 올바르지 않습니다.');
        }
        if (!controller.signal.aborted) setEvents(data);
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : '이벤트를 불러올 수 없습니다.');
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }

    loadEvents();
    return () => controller.abort();
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>Security Event Table</h2>
      {loading ? <p role="status">이벤트를 불러오는 중입니다.</p> :
        error ? <p role="alert">{error}</p> :
        events.length === 0 ? <p>저장된 이벤트가 없습니다.</p> : (
      <table border="1" cellPadding="10" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: '#f4f4f4' }}>
            <th>ID</th>
            <th>Source Type</th>
            <th>Event Time</th>
            <th>Source IP</th>
            <th>Action</th>
            <th>Request Path</th>
            <th>HTTP Status / Result</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{event.id}</td>
              <td>{event.source_type}</td>
              <td>{event.event_time}</td>
              <td>{event.source_ip ?? '-'}</td>
              <td>{event.action}</td>
              <td>{event.request_path || '-'}</td>
              <td>{event.http_status ?? (event.result || '-')}</td>
            </tr>
          ))}
        </tbody>
      </table>
      )}
    </div>
  );
}
