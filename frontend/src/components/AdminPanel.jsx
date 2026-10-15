import React, { useCallback, useEffect, useRef, useState } from 'react';
import { formatTime, go, ruleLabel } from '../api';
import { Badge, RiskBadge } from './Status';

const API = '/api/admin-panel/';
const KIND = { auto_block: '자동 차단', manual_block: '수동 차단', unblock: '차단 해제', web_block: '웹 차단', web_unblock: '웹 차단 해제' };
const STATUS_TONE = { succeeded: 'success', skipped: 'neutral', failed: 'danger', unknown: 'warning' };
const STATUS_LABEL = { succeeded: '성공', skipped: '미실행', failed: '실패', unknown: '확인 불가' };
const FAILURE = {
  not_eligible: '대상 아님', invalid_ip: 'IP 오류', config: '설정', ssh_error: 'SSH 오류', sudo_denied: 'sudo 거부',
  timeout: '타임아웃', command_failed: '명령 실패', rule_still_present: '규칙 잔존', rule_not_present: '규칙 미적용',
  fixture: '테스트 IP', not_approved: '승인 목록 외', not_detected: '탐지 이력 없음', allowlisted: '보호 대상',
  not_public: '차단 불가 주소', self: '관리자 본인 IP',
};
const HTTP_CHECK = { success: '검증 성공', failed: '검증 실패' };
const RECONNECT = { failed: '실패(차단됨)', succeeded: '성공(접속 가능)' };
const UFW_SHORT = { present: '차단', absent: '없음', unchecked: '미확인' };
const LEVEL_ORDER = { High: 3, Medium: 2, Low: 1 };
const SORTS = {
  risk: { label: '위험도 높은 순', compare: (a, b) => (b.risk?.score ?? -1) - (a.risk?.score ?? -1) },
  latest: { label: '최신 탐지 순', compare: (a, b) => new Date(b.latest_alert_at) - new Date(a.latest_alert_at) },
  alerts: { label: '경보 많은 순', compare: (a, b) => b.alert_count - a.alert_count },
  ip: { label: 'IP 순', compare: (a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }) },
};
const LEVELS = ['전체', 'High', 'Medium', 'Low', '미판정'];
// Commands shown for confirmation only; the server builds its own from the validated IP.
const WEB_HELPER = '/usr/local/sbin/mini-soc-webblock';
const SSH_HELPER = '/usr/local/sbin/mini-soc-sshblock';
const ACTIONS = {
  block: { scope: 'ssh', title: 'SSH 접속을 차단할까요?', button: 'SSH 차단 실행', path: 'threats/block/',
    command: (ip) => `sudo -n ${SSH_HELPER} block ${ip}  (→ ufw prepend deny proto tcp from ${ip} to any port 22)`,
    note: '이 IP에서 피해 서버 SSH(22/tcp)로 들어오는 새 접속만 차단합니다. 웹 서비스(HTTP) 접근과 다른 UFW 규칙은 바뀌지 않으며, 이미 연결된 세션은 유지될 수 있습니다.' },
  unblock: { scope: 'ssh', title: 'SSH 차단을 해제할까요?', button: 'SSH 차단 해제 실행', path: 'threats/unblock/',
    command: (ip) => `sudo -n ${SSH_HELPER} unblock ${ip}  (→ ufw delete deny proto tcp from ${ip} to any port 22)`,
    note: '해제하면 이 IP가 피해 서버 SSH(22/tcp)에 다시 접속을 시도할 수 있습니다.' },
  webBlock: { scope: 'web', title: '웹 접근을 차단할까요?', button: '웹 차단 실행', path: 'threats/web-block/',
    command: (ip) => `sudo -n ${WEB_HELPER} block ${ip}`,
    note: '피해 서버 Nginx 8080 서비스에 이 IP의 요청이 오면 403을 반환합니다. SSH, Apache 80, Juice Shop 3000은 바뀌지 않습니다.' },
  webUnblock: { scope: 'web', title: '웹 차단을 해제할까요?', button: '웹 차단 해제 실행', path: 'threats/web-unblock/',
    command: (ip) => `sudo -n ${WEB_HELPER} unblock ${ip}`,
    note: '해제하면 이 IP가 Nginx 8080 서비스에 다시 접근할 수 있습니다.' },
};
const SCOPE = { ssh: { name: 'SSH', where: 'UFW', port: (data) => `${data.blocked_port} (SSH)` },
  web: { name: '웹', where: 'Nginx 차단 목록', port: (data) => `${data.web_port} (Nginx 웹)` } };

function csrfToken() {
  return document.cookie.split('; ').find((c) => c.startsWith('csrftoken='))?.slice('csrftoken='.length) ?? '';
}

// Same-origin requests through the Vite /api proxy. Authentication is the Django session cookie
// (HttpOnly); nothing is kept in localStorage. The server decides every permission.
async function call(path, body) {
  const post = body !== undefined;
  try {
    const response = await fetch(API + path, {
      method: post ? 'POST' : 'GET',
      credentials: 'same-origin',
      headers: post ? { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() } : {},
      body: post ? JSON.stringify(body) : undefined,
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { detail: `서버에 연결하지 못했습니다 (${err instanceof Error ? err.message : err}).` } };
  }
}

function Login({ onLogin }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError('');
    const result = await call('login/', { username: form.get('username'), password: form.get('password') });
    setBusy(false);
    if (result.ok) onLogin(result.data);
    else setError(result.data.detail ?? `로그인 실패 (HTTP ${result.status})`);
  }

  return (
    <section className="admin-login">
      <span className="kicker">ADMIN · 관리자 전용</span>
      <h1 className="screen-title">관리자 로그인</h1>
      <p className="screen-note">SSH 차단 관리는 관제 서버의 관리자(superuser) 계정으로 로그인한 뒤 사용할 수 있습니다.</p>
      <form className="admin-form" onSubmit={submit}>
        <label>아이디<input name="username" autoComplete="username" required autoFocus /></label>
        <label>비밀번호<input name="password" type="password" autoComplete="current-password" required /></label>
        {error && <p className="state state-error" role="alert">{error}</p>}
        <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? '확인 중…' : '로그인'}</button>
      </form>
    </section>
  );
}

function ConfirmDialog({ pending, port, onCancel, onConfirm }) {
  const action = ACTIONS[pending.action];
  const scope = SCOPE[action.scope];
  const ref = useRef(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog ref={ref} className="admin-dialog" onCancel={onCancel} aria-labelledby="action-title">
      <span className="kicker">확인 필요 · 피해 서버 {action.scope === 'web' ? '웹 접근' : '방화벽'} 변경</span>
      <h2 id="action-title">{action.title}</h2>
      <dl className="margin-facts">
        <div><dt>대상 IP</dt><dd className="mono">{pending.ip}</dd></div>
        <div><dt>대상 포트</dt><dd className="mono">{port}</dd></div>
        <div><dt>실행 명령</dt><dd className="mono">{action.command(pending.ip)}</dd></div>
      </dl>
      <p className="note">
        {action.note} 서버가 실행 직전에 {scope.where} 상태를 다시 읽고, 실행 후 한 번 더 읽어 결과를 기록합니다.
        과거 차단·검증 기록은 바뀌지 않습니다.
      </p>
      <div className="admin-actions">
        <button type="button" className="btn" onClick={onCancel} autoFocus>취소</button>
        <button type="button" className="btn btn-danger" onClick={onConfirm}>{action.button}</button>
      </div>
    </dialog>
  );
}

function LastAction({ action }) {
  if (!action) return <span className="muted">조치 이력 없음</span>;
  return (
    <>
      {KIND[action.kind]} <Badge tone={STATUS_TONE[action.execution_status]}>{STATUS_LABEL[action.execution_status] ?? action.execution_status}</Badge>
      <span className="sub mono">{formatTime(action.at)}</span>
    </>
  );
}

// The button follows the state read from the victim, never the stored history.
function RowAction({ threat, state, config, busy, onCheck, onAsk }) {
  if (threat.is_fixture) return <span className="muted">조치 대상 아님</span>;
  const readOnly = <span className="muted" title={threat.read_only_reason}>SSH 조회 전용 · {FAILURE[threat.read_only_kind] ?? threat.read_only_kind}</span>;
  if (!threat.actionable && !threat.has_past_block) return readOnly;
  if (busy) return <span className="muted" role="status">처리 중…</span>;
  if (!state) return <button type="button" className="btn btn-small" onClick={onCheck}>상태 확인</button>;
  if (state === 'present') {
    const ok = config.unblock_enabled && threat.ssh_unblock_allowed;
    return (
      <button type="button" className="btn btn-small" disabled={!ok} onClick={() => onAsk('unblock')}
        title={ok ? undefined : config.unblock_enabled ? '이 시스템이 만든 차단 기록이 없습니다.' : `${config.settings.unblock}가 꺼져 있습니다.`}>
        SSH 차단 해제
      </button>
    );
  }
  if (!threat.actionable) return readOnly;
  return (
    <button type="button" className="btn btn-small btn-danger" disabled={!config.manual_block_enabled} onClick={() => onAsk('block')}
      title={config.manual_block_enabled ? undefined : `${config.settings.manual_block}가 꺼져 있습니다.`}>
      {threat.has_past_block ? 'SSH 재차단' : 'SSH 차단'}
    </button>
  );
}

// Same rule for the Nginx 8080 web block: only the state read from the victim's blocklist counts.
function WebRowAction({ threat, state, config, busy, onCheck, onAsk }) {
  if (threat.is_fixture) return null;
  if (busy) return <span className="muted" role="status">처리 중…</span>;
  if (state === 'present') {
    const ok = config.web_block_enabled && threat.web_unblock_allowed;
    return (
      <button type="button" className="btn btn-small" disabled={!ok} onClick={() => onAsk('webUnblock')}
        title={ok ? undefined : config.web_block_enabled ? '경보 기록이 없는 IP는 해제할 수 없습니다.' : `${config.settings.web_block}가 꺼져 있습니다.`}>
        웹 차단 해제
      </button>
    );
  }
  if (!threat.web_actionable) return <span className="muted" title={threat.web_read_only_reason}>웹 조회 전용 · {FAILURE[threat.web_read_only_kind] ?? threat.web_read_only_kind}</span>;
  if (!state) return <button type="button" className="btn btn-small" onClick={onCheck}>웹 상태 확인</button>;
  return (
    <button type="button" className="btn btn-small btn-danger" disabled={!config.web_block_enabled} onClick={() => onAsk('webBlock')}
      title={config.web_block_enabled ? undefined : `${config.settings.web_block}가 꺼져 있습니다.`}>
      웹 차단
    </button>
  );
}

function Manager({ username, onLogout, onDenied }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [ufw, setUfw] = useState({ states: {}, checkedAt: null, error: '' });
  const [web, setWeb] = useState({ states: {}, checkedAt: null, error: '' });
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState({});
  const [pending, setPending] = useState(null);
  const [notice, setNotice] = useState(null);
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('전체');
  const [sort, setSort] = useState('risk');

  const denied = useCallback((result) => {
    if (result.status === 401 || result.status === 403 && !result.data.outcome) {
      onDenied();
      return true;
    }
    return false;
  }, [onDenied]);

  const apply = useCallback((result) => {
    if (denied(result)) return;
    if (!result.ok) {
      setError(`기록을 불러오지 못했습니다 (HTTP ${result.status}).`);
      return;
    }
    setError('');
    setData(result.data);
  }, [denied]);
  const load = useCallback(() => call('threats/').then(apply), [apply]);

  useEffect(() => {
    call('threats/').then(apply);
  }, [apply]);

  // Reads SSH (UFW) and web (Nginx blocklist) state together; each failure is reported on its own.
  async function checkStatus() {
    setChecking(true);
    const [ssh, nginx] = await Promise.all([call('ufw-status/', {}), call('web-status/', {})]);
    setChecking(false);
    if (denied(ssh) || denied(nginx)) return;
    const read = (result, label) => {
      if (result.ok && !result.data.failure_kind) return { states: result.data.states, checkedAt: result.data.checked_at, error: '' };
      // An unreadable state is unknown, not "unblocked": every change button stays off.
      const reason = result.ok ? `${FAILURE[result.data.failure_kind] ?? result.data.failure_kind}: ${result.data.detail}` : `HTTP ${result.status}`;
      return { states: {}, checkedAt: null, error: `피해 서버 ${label} 상태를 읽지 못했습니다 — ${reason}` };
    };
    setUfw(read(ssh, 'UFW'));
    setWeb(read(nginx, 'Nginx 웹 차단'));
  }

  async function run({ action, ip }) {
    setPending(null);
    setBusy((s) => ({ ...s, [ip]: true }));
    const result = await call(ACTIONS[action].path, { ip, confirm: true });
    setBusy((s) => ({ ...s, [ip]: false }));
    if (denied(result)) return;
    const d = result.data;
    const scope = ACTIONS[action].scope;
    // The server re-read the victim after the change; an unreadable result leaves the state unknown.
    (scope === 'web' ? setWeb : setUfw)((s) => {
      const states = { ...s.states };
      if (d.ufw_state === 'present' || d.ufw_state === 'absent') states[ip] = d.ufw_state;
      else delete states[ip];
      return { ...s, states, checkedAt: d.checked_at ?? s.checkedAt };
    });
    const messages = {
      blocked: ['success', `${ip} SSH(22/tcp) 차단을 적용했고, 실행 후 UFW에서 DENY 규칙을 확인했습니다.`],
      already_blocked: ['neutral', `${ip}은 이미 SSH 차단 중이어서 중복 규칙을 추가하지 않았습니다.`],
      unblocked: ['success', `${ip} SSH 차단을 해제했고, 실행 후 UFW에 규칙이 없음을 확인했습니다. Kali 재접속은 별도 검증 항목입니다.`],
      already_unblocked: ['neutral', `${ip}에는 이미 차단 규칙이 없어 삭제 명령을 보내지 않았습니다.`],
    };
    const webMessages = {
      blocked: ['success', `${ip} 웹(Nginx 8080) 차단을 적용했고, 실행 후 차단 목록에서 확인했습니다. 공격 환경의 HTTP 403 확인은 별도 검증 항목입니다.`],
      already_blocked: ['neutral', `${ip}은 이미 웹 차단 중이어서 다시 추가하지 않았습니다.`],
      unblocked: ['success', `${ip} 웹 차단을 해제했고, 실행 후 차단 목록에 없음을 확인했습니다. HTTP 200 복구 확인은 별도 검증 항목입니다.`],
      already_unblocked: ['neutral', `${ip}은 웹 차단 목록에 없어 해제 명령을 보내지 않았습니다.`],
    };
    const [tone, text] = (scope === 'web' ? webMessages : messages)[d.outcome]
      ?? ['danger', `${ip} ${ACTIONS[action].button.replace(' 실행', '')} 실패 — ${FAILURE[d.failure_kind] ?? d.failure_kind ?? `HTTP ${result.status}`}: ${d.detail ?? ''}`];
    setNotice({ tone, text });
    load();
  }

  async function logout() {
    await call('logout/', {});
    onLogout();
  }

  const threats = data?.threats ?? [];
  const real = threats.filter((t) => !t.is_fixture);
  const blocked = real.filter((t) => ufw.states[t.ip] === 'present').length;
  const webBlocked = real.filter((t) => web.states[t.ip] === 'present').length;
  const checkedAt = ufw.checkedAt || web.checkedAt;
  const needle = query.trim();
  const rows = threats
    .filter((t) => !needle || t.ip.includes(needle))
    .filter((t) => level === '전체' || (t.risk?.level ?? '미판정') === level)
    .sort((a, b) => a.is_fixture - b.is_fixture || SORTS[sort].compare(a, b) || (LEVEL_ORDER[b.risk?.level] ?? 0) - (LEVEL_ORDER[a.risk?.level] ?? 0));

  return (
    <div className="admin">
      <header className="admin-head">
        <div>
          <span className="kicker">ADMIN · 관리자 전용</span>
          <h1 className="screen-title">위협 IP 관리</h1>
          <p className="screen-note">경보가 발생한 출발지 IP별로 탐지 내용과 피해 서버의 차단 상태를 관리합니다. SSH 차단은 UFW 22/tcp에, 웹 차단은 Nginx 8080 서비스에만 적용되며 서로 영향을 주지 않습니다.</p>
        </div>
        <div className="admin-user">
          <span><strong>{username}</strong> 로그인 중</span>
          <button type="button" className="btn btn-small" onClick={logout}>로그아웃</button>
        </div>
      </header>

      <dl className="admin-stats">
        <div><dt>탐지 IP</dt><dd>{data ? real.length : '…'}</dd><span className="sub">{data && threats.length > real.length ? `테스트 IP ${threats.length - real.length}개 별도` : '경보 발생 출발지'}</span></div>
        <div><dt>실제 차단 중 · SSH / 웹</dt><dd className={blocked || webBlocked ? 'tone-danger' : undefined}>{ufw.checkedAt ? blocked : '—'} / {web.checkedAt ? webBlocked : '—'}</dd><span className="sub">{checkedAt ? `${formatTime(checkedAt)} UFW·Nginx 확인` : '피해 서버 상태 미확인'}</span></div>
        <div><dt>주요 위험 IP</dt><dd className={real.some((t) => t.risk?.level === 'High') ? 'tone-danger' : undefined}>{data ? real.filter((t) => t.risk?.level === 'High').length : '…'}</dd><span className="sub">위험도 High</span></div>
      </dl>

      {data?.config_error && <p className="state state-error" role="alert">SSH 사설 허용 범위 설정 오류: {data.config_error}</p>}
      {data?.overrides_error && <p className="state state-error" role="alert">설정 override 오류로 모든 차단이 꺼져 있습니다: {data.overrides_error}</p>}
      {data?.web_config_error && <p className="state state-error" role="alert">웹 차단 승인 목록 설정 오류: {data.web_config_error}</p>}
      {ufw.error && <p className="admin-notice tone-danger" role="alert">{ufw.error} 상태를 확인할 수 없는 동안에는 SSH 차단·해제를 실행할 수 없습니다.</p>}
      {web.error && <p className="admin-notice tone-danger" role="alert">{web.error} 상태를 확인할 수 없는 동안에는 웹 차단·해제를 실행할 수 없습니다.</p>}
      {notice && <p className={`admin-notice tone-${notice.tone}`} role="status">{notice.text}</p>}
      {error && <p className="state state-error" role="alert">{error} <button type="button" className="link" onClick={load}>다시 조회</button></p>}

      <section>
        <div className="admin-toolbar">
          <label className="admin-search">IP 검색<input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="예: 192.168.1" /></label>
          <div className="filter" role="group" aria-label="위험도 필터">
            {LEVELS.map((l) => (
              <button key={l} type="button" className={l === level ? 'active' : undefined} aria-pressed={l === level} onClick={() => setLevel(l)}>{l}</button>
            ))}
          </div>
          <label className="admin-search">정렬
            <select value={sort} onChange={(e) => setSort(e.target.value)}>
              {Object.entries(SORTS).map(([key, s]) => <option key={key} value={key}>{s.label}</option>)}
            </select>
          </label>
          <span className="admin-toolbar-end">
            <button type="button" className="btn btn-small" onClick={load}>새로고침</button>
            <button type="button" className="btn btn-small btn-primary" disabled={checking} onClick={checkStatus}>{checking ? '확인 중…' : '차단 상태 확인'}</button>
          </span>
        </div>

        {!data && !error && <div className="state" role="status">불러오는 중…</div>}
        {data && rows.length === 0 && <div className="state">{threats.length ? '조건에 맞는 IP 없음' : '경보가 발생한 IP 없음'}</div>}
        {data && rows.length > 0 && (
          <div className="admin-table">
            <table className="log">
              <thead>
                <tr><th>IP 주소</th><th>탐지 유형</th><th>경보</th><th>최신 탐지</th><th>위험도</th><th>보안 사고</th><th>SSH 차단 상태 (UFW)</th><th>웹 차단 상태 (Nginx 8080)</th><th>최근 차단·해제</th><th>관리 작업</th></tr>
              </thead>
              <tbody>
                {rows.map((t) => {
                  const state = ufw.states[t.ip];
                  const webState = web.states[t.ip];
                  return (
                    <tr key={t.ip} className={t.is_fixture ? 'row-fixture' : undefined}>
                      <td className="mono"><strong>{t.ip}</strong>{t.is_fixture && <span className="sub">테스트·문서용 IP</span>}</td>
                      <td>{t.rule_types.map((r) => <span key={r} className="admin-rule">{ruleLabel(r)}</span>)}</td>
                      <td className="mono">{t.alert_count}</td>
                      <td className="mono">{formatTime(t.latest_alert_at)}</td>
                      <td>{t.risk ? <RiskBadge level={t.risk.level} score={t.risk.score} /> : <span className="muted">미판정</span>}</td>
                      <td>{t.incidents.length ? t.incidents.map((i) => (
                        <button key={i.id} type="button" className="link admin-rule" onClick={() => go('incidents', i.id)}>사고 #{i.id}</button>
                      )) : <span className="muted">없음</span>}</td>
                      <td aria-live="polite">
                        {t.is_fixture ? <span className="muted">해당 없음</span>
                          : state === 'present' ? <Badge tone="danger">SSH 차단 중</Badge>
                            : state === 'absent' ? <Badge tone="success">차단 없음</Badge>
                              : <Badge tone="warning">미확인</Badge>}
                      </td>
                      <td aria-live="polite">
                        {t.is_fixture ? <span className="muted">해당 없음</span>
                          : webState === 'present' ? <Badge tone="danger">웹 차단 중</Badge>
                            : webState === 'absent' ? <Badge tone="success">차단 없음</Badge>
                              : <Badge tone="warning">미확인</Badge>}
                      </td>
                      <td><LastAction action={t.last_action} /></td>
                      <td>
                        <span className="admin-rule">
                          <RowAction threat={t} state={state} config={data} busy={busy[t.ip] || checking}
                            onCheck={checkStatus} onAsk={(action) => setPending({ action, ip: t.ip })} />
                        </span>
                        <span className="admin-rule">
                          <WebRowAction threat={t} state={webState} config={data} busy={busy[t.ip] || checking}
                            onCheck={checkStatus} onAsk={(action) => setPending({ action, ip: t.ip })} />
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="note">
          SSH 차단 상태는 피해 서버의 <span className="mono">ufw status</span>, 웹 차단 상태는 Nginx 8080 차단 목록을 읽은 결과이며, 과거 성공 기록으로 추정하지 않습니다.
          SSH 차단은 SSH 무차별 대입 경보가 발생한 IP만, 웹 차단은 경보가 발생한 IP만 대상으로 합니다.
          두 기능 모두 보호 대상·관리자 본인 IP와 루프백·링크 로컬·예약 주소를 거부하며, 사설 IP는 명시한 허용 범위
          (SSH: {data?.ssh_private_ranges?.join(', ') || '없음'}, 웹: {data?.web_private_ranges?.join(', ') || '없음'})에 있을 때만 가능합니다. 테스트·문서용 IP는 조회 전용입니다.
        </p>
      </section>

      <section>
        <h2 className="label">차단·해제 작업 이력</h2>
        {!data?.history.length ? <div className="state">작업 기록 없음</div> : (
          <div className="admin-table">
            <table className="log">
              <thead>
                <tr><th>시각</th><th>작업</th><th>대상 IP</th><th>수행</th><th>실행 결과</th><th>상태 전 → 후</th><th>비고</th></tr>
              </thead>
              <tbody>
                {data.history.map((a) => (
                  <tr key={`${a.kind}-${a.id}`}>
                    <td className="mono">{formatTime(a.at)}</td>
                    <td>{KIND[a.kind]} <span className="mono muted">#{a.id}</span></td>
                    <td className="mono">{a.target_ip ?? '-'}</td>
                    <td>{a.requested_by || <span className="muted">자동 대응</span>}</td>
                    <td><Badge tone={STATUS_TONE[a.execution_status]}>{STATUS_LABEL[a.execution_status] ?? a.execution_status}</Badge></td>
                    <td>{a.ufw_before_result ? `${UFW_SHORT[a.ufw_before_result]} → ${UFW_SHORT[a.ufw_after_result]}` : <span className="muted">별도 검증 기록</span>}</td>
                    <td>
                      {a.failure_kind ? `${FAILURE[a.failure_kind] ?? a.failure_kind}: ` : ''}{a.failure_reason}
                      {a.http_check_status != null && <span className="sub">공격 환경 HTTP {a.http_check_status} · {HTTP_CHECK[a.http_check_result] ?? a.http_check_result}</span>}
                      {a.reconnect_result && a.reconnect_result !== 'unchecked' && <span className="sub">공격 환경 SSH 새 접속 {RECONNECT[a.reconnect_result]}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="note">명령 실행 성공과 Kali SSH 재접속·HTTP 응답(403/200) 확인 결과는 별개의 검증 항목입니다.</p>
      </section>

      {pending && <ConfirmDialog pending={pending} port={SCOPE[ACTIONS[pending.action].scope].port(data)} onCancel={() => setPending(null)} onConfirm={() => run(pending)} />}
    </div>
  );
}

export default function AdminPanel() {
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');

  const apply = useCallback((result) => {
    if (result.ok) {
      setError('');
      setSession(result.data);
    } else {
      setError(result.data.detail ?? `세션을 확인하지 못했습니다 (HTTP ${result.status}).`);
    }
  }, []);
  const refresh = useCallback(() => call('session/').then(apply), [apply]);

  useEffect(() => {
    call('session/').then(apply);
  }, [apply]);

  if (error) {
    return <div className="state state-error" role="alert">{error} <button type="button" className="link" onClick={refresh}>다시 조회</button></div>;
  }
  if (!session) return <div className="state" role="status">세션 확인 중…</div>;
  if (!session.authenticated) return <Login onLogin={setSession} />;
  return <Manager username={session.username} onLogout={refresh} onDenied={refresh} />;
}
