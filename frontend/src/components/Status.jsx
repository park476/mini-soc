import React from 'react';

// Shows loading / error (with retry) / empty states; renders children only with real data.
export default function Status({ state, empty = '기록 없음', children }) {
  if (state.loading && !state.data) return <p className="state" role="status">불러오는 중…</p>;
  if (state.error) {
    return (
      <p className="state state-error" role="alert">
        기록을 불러오지 못했습니다 ({state.error}).{' '}
        <button type="button" className="link-button" onClick={state.reload}>다시 조회</button>
      </p>
    );
  }
  if (Array.isArray(state.data) && state.data.length === 0) return <p className="state">{empty}</p>;
  if (!state.data) return null;
  return children;
}

export function RiskBadge({ level, score }) {
  return (
    <span className={`risk risk-${String(level).toLowerCase()}`}>
      {score !== undefined && <strong>{score}</strong>} {level}
    </span>
  );
}

export function SourceBadge({ type }) {
  return <span className={`source source-${type}`}>{type === 'ssh' ? 'SSH' : 'Nginx'}</span>;
}
