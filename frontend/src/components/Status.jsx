import React from 'react';
import { EXECUTION, go, VERIFY } from '../api';

// Shows loading / error (with retry) / empty states; renders children only with real data.
export default function Status({ state, empty = '기록 없음', children }) {
  if (state.loading && !state.data) return <div className="state" role="status">불러오는 중…</div>;
  if (state.error) {
    return (
      <div className="state state-error" role="alert">
        기록을 불러오지 못했습니다 ({state.error}).{' '}
        <button type="button" className="link" onClick={state.reload}>다시 조회</button>
      </div>
    );
  }
  if (Array.isArray(state.data) && state.data.length === 0) return <div className="state">{empty}</div>;
  if (!state.data) return null;
  return children;
}

// Pills are reserved for status values (risk level, execution / verification result).
export function Badge({ tone = 'neutral', children }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

const RISK_TONE = { high: 'danger', medium: 'warning', low: 'neutral' };

export function RiskBadge({ level, score }) {
  const tone = RISK_TONE[String(level).toLowerCase()] ?? 'neutral';
  return <span className={`pill pill-${tone}`}>{score !== undefined && <strong>{score}</strong>} {level}</span>;
}

// Log source is a category, not a status: plain small caps text.
export function SourceLabel({ type }) {
  return <span className={`src src-${type}`}>{type === 'ssh' ? 'SSH' : 'NGINX'}</span>;
}

function resultTone(result) {
  if (result === 'success') return 'success';
  if (result === 'failure') return 'danger';
  const status = Number(result);
  if (status >= 500) return 'danger';
  if (status >= 400) return 'warning';
  if (status >= 200) return 'success';
  return 'neutral';
}

// In dense lists the result is coloured text; the pill form is used once, in the inspector.
export function ResultText({ result }) {
  return <span className={`tone-${resultTone(result)}`}>{result}</span>;
}

export function ResultBadge({ result }) {
  return <Badge tone={resultTone(result)}>{result}</Badge>;
}

const EXECUTION_TONE = { succeeded: 'success', failed: 'danger', skipped: 'neutral', unknown: 'warning' };
const VERIFY_TONE = { success: 'success', failed: 'danger', unverified: 'warning' };

export function ExecutionBadge({ status }) {
  return <Badge tone={EXECUTION_TONE[status] ?? 'neutral'}>{EXECUTION[status] ?? status}</Badge>;
}

export function VerificationBadge({ record }) {
  const v = record.verification;
  if (!v) return <Badge tone="warning">미검증 (검증 기록 없음)</Badge>;
  return <Badge tone={VERIFY_TONE[v.verification_status]}>{VERIFY[v.verification_status]}</Badge>;
}

export function IdLinks({ ids, screen, prefix = '#' }) {
  return (
    <span className="id-links">
      {ids.map((id) => (
        <button key={id} type="button" className="link" onClick={() => go(screen, id)}>{prefix}{id}</button>
      ))}
    </span>
  );
}
