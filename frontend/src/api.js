import { useCallback, useEffect, useState } from 'react';

export function useApi(url) {
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
  const current = result.key === key;
  return {
    loading: Boolean(url) && !current,
    error: current ? result.error : '',
    data: current ? result.data : null,
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
