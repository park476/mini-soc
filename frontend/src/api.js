import { useCallback, useEffect, useState } from 'react';

// pollMs (optional): refetch on that interval and keep showing the last data while it reloads.
export function useApi(url, pollMs) {
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState({ key: null, error: '', data: null });
  const key = url ? `${url}#${attempt}` : null;

  useEffect(() => {
    if (!url) return undefined;
    const controller = new AbortController();
    fetch(url, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((data) => setResult({ key: `${url}#${attempt}`, error: '', data }))
      .catch((err) => {
        if (!controller.signal.aborted) {
          setResult({ key: `${url}#${attempt}`, error: err instanceof Error ? err.message : String(err), data: null });
        }
      });
    return () => controller.abort();
  }, [url, attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);
  useEffect(() => {
    if (!url || !pollMs) return undefined;
    const timer = setInterval(reload, pollMs);
    return () => clearInterval(timer);
  }, [url, pollMs, reload]);
  const current = result.key === key;
  const stale = Boolean(pollMs) && !current && result.data !== null && result.key?.startsWith(`${url}#`);
  return {
    loading: Boolean(url) && !current && !stale,
    error: current ? result.error : '',
    data: current || stale ? result.data : null,
    reload,
  };
}

const TIME_FORMAT = new Intl.DateTimeFormat('sv-SE', {
  timeZone: 'Asia/Seoul',
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
});

// All times are shown in KST; API values are ISO strings in UTC.
export function formatTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : TIME_FORMAT.format(date);
}

export const RULES = {
  ssh_brute_force: { label: 'SSH 무차별 대입', source: 'SSH' },
  nginx_scan: { label: 'Nginx 스캔', source: 'Nginx' },
  nginx_suspicious_path: { label: 'Nginx 의심 경로 접근', source: 'Nginx' },
};
export const RULE_ORDER = Object.keys(RULES);

export function ruleLabel(ruleType) {
  return RULES[ruleType]?.label ?? ruleType;
}

export function byTime(field) {
  return (a, b) => new Date(a[field]) - new Date(b[field]) || a.id - b.id;
}

export function go(screen, id) {
  window.location.hash = id ? `/${screen}/${id}` : `/${screen}`;
}

export const EXECUTION = {
  succeeded: 'UFW 차단 명령 실행 성공',
  failed: '실행 실패',
  skipped: '미실행 (허용 목록 제외)',
  unknown: '확인 불가',
};
export const VERIFY = { success: '검증 성공', failed: '검증 실패', unverified: '미검증' };

export function verificationLabel(record) {
  return record.verification ? VERIFY[record.verification.verification_status] : '미검증 (검증 기록 없음)';
}

// Clickable table rows: mouse click plus Enter/Space for keyboard users.
export function rowProps(onActivate, selected = false) {
  return {
    tabIndex: 0,
    className: selected ? 'row-link selected' : 'row-link',
    'aria-current': selected ? 'true' : undefined,
    onClick: onActivate,
    onKeyDown: (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        onActivate();
      }
    },
  };
}

// Display-only gap between two stored timestamps, e.g. "+1분 20초".
export function formatGap(from, to) {
  const seconds = Math.round((new Date(to) - new Date(from)) / 1000);
  if (!Number.isFinite(seconds)) return '';
  const abs = Math.abs(seconds);
  const text = abs >= 60 ? `${Math.floor(abs / 60)}분${abs % 60 ? ` ${abs % 60}초` : ''}` : `${abs}초`;
  return `${seconds < 0 ? '-' : '+'}${text}`;
}
