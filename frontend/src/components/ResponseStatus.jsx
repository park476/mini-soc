import React, { useEffect, useRef, useState } from 'react';
import { formatTime, go, rowProps, ruleLabel, useApi, VERIFY } from '../api';
import Status, { Badge, ExecutionBadge, IdLinks, VerificationBadge } from './Status';

const ADMIN = '/api/admin-panel/';
const WEB_HELPER = '/usr/local/sbin/mini-soc-webblock';

function csrfToken() {
  return document.cookie.split('; ').find((c) => c.startsWith('csrftoken='))?.slice('csrftoken='.length) ?? '';
}

// Reuses the existing admin-panel web-unblock endpoint (superuser session + CSRF); no new engine.
async function adminWebUnblock(ip) {
  try {
    await fetch(`${ADMIN}session/`, { credentials: 'same-origin' }); // ensures the csrftoken cookie
    const res = await fetch(`${ADMIN}threats/web-unblock/`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
      body: JSON.stringify({ ip, confirm: true }),
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { detail: err instanceof Error ? err.message : String(err) } };
  }
}

const ALLOWLIST = { excluded: '차단 제외 (허용 목록)', not_excluded: '제외 아님', unknown: '확인 불가' };
const UFW = { present: '규칙 존재 확인', absent: '규칙 없음', unchecked: '미확인' };
const RECONNECT = { failed: '접속 실패 확인', succeeded: '접속 성공 (차단 안 됨)', unchecked: '미확인' };
const EXEC = { succeeded: '성공', skipped: '미실행', failed: '실패', unknown: '확인 불가' };
const EXEC_TONE = { succeeded: 'success', skipped: 'neutral', failed: 'danger', unknown: 'warning' };
const STEP_MARK = { done: '✓', fail: '✕', skip: '–', pending: '…' };
const STEP_TONE = { done: 'success', fail: 'danger', skip: 'neutral', pending: 'warning' };

// Polls a read-only endpoint every `ms`; bumping `reload` forces an immediate refetch.
function usePolling(url, ms, reload) {
  const [state, setState] = useState({ data: null, error: '', loaded: false });
  useEffect(() => {
    let alive = true;
    let timer;
    const tick = async () => {
      try {
        const res = await fetch(url, { credentials: 'same-origin' });
        const data = await res.json().catch(() => null);
        if (alive) setState({ data, error: res.ok ? '' : `HTTP ${res.status}`, loaded: true });
      } catch (err) {
        if (alive) setState((s) => ({ ...s, error: err instanceof Error ? err.message : String(err), loaded: true }));
      }
      if (alive) timer = setTimeout(tick, ms);
    };
    tick();
    return () => { alive = false; clearTimeout(timer); };
  }, [url, ms, reload]);
  return state;
}

function UnblockDialog({ ip, onCancel, onConfirm }) {
  const ref = useRef(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog ref={ref} className="admin-dialog" onCancel={onCancel} aria-labelledby="soar-unblock-title">
      <span className="kicker">확인 필요 · 피해 서버 웹 접근 변경</span>
      <h2 id="soar-unblock-title">웹 차단을 즉시 해제할까요?</h2>
      <dl className="margin-facts">
        <div><dt>대상 IP</dt><dd className="mono">{ip}</dd></div>
        <div><dt>작업</dt><dd>Nginx 8080 차단 목록에서 이 IP의 deny 규칙 제거</dd></div>
        <div><dt>실행 명령</dt><dd className="mono">sudo -n {WEB_HELPER} unblock {ip}</dd></div>
      </dl>
      <p className="note">
        관리자(superuser) 권한으로 실행합니다. 서버가 실제 차단 상태를 다시 확인하고, 이미 해제돼 있으면 명령을 보내지 않습니다.
        TTL 자동 해제와 구분해 관리자 수동 해제로 기록됩니다.
      </p>
      <div className="admin-actions">
        <button type="button" className="btn" onClick={onCancel} autoFocus>취소</button>
        <button type="button" className="btn btn-danger" onClick={onConfirm}>즉시 해제 실행</button>
      </div>
    </dialog>
  );
}

function httpState(record) {
  // '미확인' until a real HTTP status was observed and recorded (record_web_check).
  if (!record || record.http_check_status == null) return { state: 'pending', text: '미확인' };
  return { state: record.http_check_result === 'success' ? 'done' : 'fail',
    text: `HTTP ${record.http_check_status} · ${record.http_check_result === 'success' ? '검증 성공' : '검증 실패'}` };
}

function caseSteps(c) {
  const a = c.alert;
  const b = c.block;
  const u = c.unblock;
  const execState = (r) => (!r ? 'pending' : r.execution_status === 'succeeded' ? 'done'
    : r.execution_status === 'skipped' ? 'skip' : r.execution_status === 'unknown' ? 'pending' : 'fail');
  const blockState = b.blocklist_state === 'present' ? 'done' : b.blocklist_state === 'absent' ? 'fail' : 'pending';
  const h403 = httpState(b);
  const h200 = httpState(u);
  return [
    { n: 1, title: 'nginx_scan 경보 발생', state: a ? 'done' : 'pending',
      meta: a ? <>경보 <IdLinks ids={[a.id]} screen="alerts" prefix="#" /> · <span className="mono">{a.source_ip}</span> · {formatTime(a.occurred_at)}</> : '경보 기록 없음' },
    { n: 2, title: 'PB-01 자동 실행', state: execState(b),
      meta: <>차단 기록 <span className="mono">#{b.id}</span> · {EXEC[b.execution_status] ?? b.execution_status} · {formatTime(b.executed_at)}</> },
    { n: 3, title: 'Nginx IP 차단', state: blockState,
      meta: <>차단 목록 재확인: <strong>{b.blocklist_state === 'present' ? '규칙 있음' : b.blocklist_state === 'absent' ? '규칙 없음' : '미확인'}</strong></> },
    { n: 4, title: 'HTTP 403 효과 검증', state: h403.state,
      meta: <>공격 환경(Kali) 실제 응답: <strong>{h403.text}</strong>{b.http_checked_at && <span className="sub">{formatTime(b.http_checked_at)} 관찰</span>}</> },
    { n: 5, title: u && u.origin === 'manual' ? '관리자 수동 해제' : 'TTL 자동 해제', state: execState(u),
      meta: u ? <>{u.origin === 'manual' ? '관리자 수동 해제' : 'TTL 자동 해제'} 기록 <span className="mono">#{u.id}</span> · {EXEC[u.execution_status] ?? u.execution_status} · {formatTime(u.executed_at)}</> : <>대기 — TTL(만료 예정 {formatTime(b.expires_at)}) 경과 후 자동 해제, 또는 관리자 즉시 해제</> },
    { n: 6, title: 'HTTP 200 복구 검증', state: h200.state,
      meta: u ? <>공격 환경(Kali) 실제 응답: <strong>{h200.text}</strong>{u.http_checked_at && <span className="sub">{formatTime(u.http_checked_at)} 관찰</span>}</> : <span className="muted">해제 후 확인 예정</span> },
  ];
}

function Timeline({ case: c }) {
  if (!c) return <div className="state">자동 대응 사례를 선택하세요.</div>;
  return (
    <ol className="soar-steps">
      {caseSteps(c).map((s) => (
        <li key={s.n} className="soar-step">
          <span className={`soar-dot tone-${STEP_TONE[s.state]}`} aria-hidden="true">{STEP_MARK[s.state]}</span>
          <div className="soar-step-body">
            <strong>{s.n} · {s.title}</strong>
            <span className="soar-step-meta">{s.meta}</span>
          </div>
        </li>
      ))}
    </ol>
  );
}

// The page's main subject: the PB-01 web auto-response that actually runs. All values come from the API.
function WebAutoConsole() {
  const [caseKey, setCaseKey] = useState(null);
  const [pending, setPending] = useState(null);
  const [notice, setNotice] = useState(null);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const poll = usePolling('/api/responses/web-auto/', 5000, reload);
  const d = poll.data;
  if (!d) return <Status state={{ loading: !poll.loaded, error: poll.error, data: null }} />;
  const cases = d.cases ?? [];
  const selected = cases.find((c) => c.key === caseKey) ?? cases[0] ?? null;
  const c = d.counts;

  async function runUnblock(ip) {
    setPending(null);
    setBusy(true);
    const r = await adminWebUnblock(ip);
    setBusy(false);
    if (r.status === 401 || (r.status === 403 && !r.data.outcome)) {
      setNotice({ tone: 'warning', text: '관리자 패널에서 superuser 로그인 후 다시 시도하세요. (서버가 권한을 재검증합니다)' });
      return;
    }
    const messages = {
      unblocked: ['success', `${ip} 웹 차단을 즉시 해제했고, 실행 후 차단 목록에서 규칙이 사라진 것을 확인했습니다. HTTP 200 복구는 공격 환경에서 별도 확인합니다.`],
      already_unblocked: ['neutral', `${ip}은 이미 차단 목록에 없어 해제 명령을 보내지 않았습니다.`],
    };
    const [tone, text] = messages[r.data.outcome]
      ?? ['danger', `${ip} 즉시 해제 실패 — ${r.data.failure_kind ? `${r.data.failure_kind}: ` : ''}${r.data.detail ?? `HTTP ${r.status}`}`];
    setNotice({ tone, text });
    setReload((n) => n + 1); // refresh timeline and block state now, not only on the 5s tick
  }

  return (
    <section className="response-main">
      <h1 className="screen-title">SOAR 자동 대응 현황</h1>
      <p className="screen-note">
        PB-01 Nginx 스캔 자동 웹 차단의 실제 실행 기록과 효과 검증입니다. 관리자 버튼 없이 분석 루프가 실행하며,
        5초마다 자동 갱신됩니다. 모든 수치는 저장된 기록에서 읽습니다.
      </p>

      <dl className="admin-stats">
        <div><dt>PB-01 상태</dt><dd className={d.enabled ? 'tone-success' : 'tone-warning'}>{d.enabled ? '설정 활성' : '설정 비활성'}</dd><span className="sub">설정 기준 (프로세스 상태 아님)</span></div>
        <div><dt>자동 차단 성공</dt><dd>{c.blocks_succeeded}</dd><span className="sub">실행 성공 기록</span></div>
        <div><dt>HTTP 403 검증</dt><dd className={c.http_verified ? 'tone-success' : undefined}>{c.http_verified}</dd><span className="sub">실제 차단 효과 확인</span></div>
        <div><dt>현재 차단 중 IP</dt><dd className={c.active ? 'tone-danger' : undefined}>{c.active}</dd><span className="sub">자동 차단 활성</span></div>
        <div><dt>자동 해제 성공</dt><dd>{c.unblocks_succeeded}</dd><span className="sub">TTL 복구</span></div>
        <div><dt>최신 자동 대응</dt><dd className="mono" style={{ fontSize: '18px' }}>{c.latest_at ? formatTime(c.latest_at) : '—'}</dd><span className="sub">마지막 실행 시각</span></div>
      </dl>

      {d.overrides_error && <p className="state state-error" role="alert">설정 override 오류로 자동 차단이 꺼졌습니다: {d.overrides_error}</p>}
      {notice && <p className={`admin-notice tone-${notice.tone}`} role="status">{notice.text}</p>}
      {poll.error && <p className="admin-notice tone-warning" role="status">실시간 갱신 오류: {poll.error} (마지막으로 받은 값 표시 중)</p>}
      <p className="note">
        트리거 <span className="mono">{d.policy.trigger_rule}</span> · 최근 {Math.round(d.policy.max_alert_age_seconds / 60)}분 경보만 ·
        시간당 최대 {d.policy.hourly_limit}건 · 자동 해제 TTL {Math.round(d.policy.ttl_seconds / 60)}분 ·
        자동 해제(TTL)는 {d.web_block_enabled ? '동작' : '대기 (수동 해제 필요)'}. 보호 목록·관제 서버 주소 제외, 과거 경보 일괄 차단 안 함.
      </p>

      <div className="soar-grid">
        <aside className="soar-cases">
          <h2 className="label">자동 대응 사례</h2>
          {cases.length === 0 ? (
            <div className="state">아직 자동 대응 기록이 없습니다. nginx_scan 경보가 발생하면 여기에 나타납니다.</div>
          ) : (
            <ol className="index">
              {cases.map((cc) => {
                const verified = cc.block.http_check_result === 'success';
                return (
                  <li key={cc.key} {...rowProps(() => setCaseKey(cc.key), (selected && cc.key === selected.key))}>
                    <span className="index-title"><span className="mono">{cc.target_ip}</span></span>
                    <span className="index-meta">
                      <Badge tone={EXEC_TONE[cc.block.execution_status] ?? 'neutral'}>{EXEC[cc.block.execution_status] ?? cc.block.execution_status}</Badge>
                      {verified && <Badge tone="success">403 검증</Badge>}
                      {cc.unblock && <Badge tone="neutral">해제됨</Badge>}
                    </span>
                    <span className="index-meta mono">차단 #{cc.block.id} · {formatTime(cc.block.executed_at)}{cc.alert && ` · 경보 #${cc.alert.id}`}</span>
                  </li>
                );
              })}
            </ol>
          )}
        </aside>
        <div className="soar-timeline">
          <div className="soar-timeline-head">
            <h2 className="label">대응 타임라인{selected && <span className="mono muted"> · {selected.target_ip}</span>}</h2>
            {selected?.active && (
              <button type="button" className="btn btn-small btn-danger" disabled={busy}
                onClick={() => setPending(selected.target_ip)}>
                {busy ? '처리 중…' : '즉시 차단 해제'}
              </button>
            )}
          </div>
          <Timeline case={selected} />
          <p className="note">
            각 단계는 실제 DB 기록(Alert · WebBlockRecord)에서 읽습니다. 관찰되지 않은 값은 ‘미확인’으로 표시하며 검증 성공을 임의로 만들지 않습니다.
            {selected?.active && ' 현재 실제 차단 중인 IP만 즉시 해제할 수 있습니다.'}
          </p>
        </div>
      </div>
      {pending && <UnblockDialog ip={pending} onCancel={() => setPending(null)} onConfirm={() => runUnblock(pending)} />}
    </section>
  );
}

// Designed SSH response path (docs 05 §4). Not an execution record; SSH auto-response has 0 records.
function Architecture() {
  return (
    <div className="arch" role="img" aria-label="SSH 자동 대응 설계 경로: 관제 서버에서 SSH로 피해 Ubuntu의 UFW를 제어하고, 피해 Ubuntu와 공격자 Kali에서 효과를 검증">
      <div className="zone zone-monitor"><span className="zone-name">관제 서버</span></div>
      <div className="zone zone-victim"><span className="zone-name">피해 Ubuntu</span></div>
      <div className="zone zone-kali"><span className="zone-name">공격자 Kali</span></div>

      <div className="node n-alert">
        <span className="node-kind">ALERT</span>
        <strong>SSH 무차별 대입 경보</strong>
        <span>ssh_brute_force 경보가 발동 조건 · 보안 사고를 기다리지 않음</span>
      </div>
      <div className="edge-down e-1"><span>trigger</span></div>
      <div className="node n-allow">
        <span className="node-kind">CONTROL</span>
        <strong>허용 목록 검사</strong>
        <span>관제 서버 등 관리 주소는 차단 제외 — 제외면 실행하지 않음</span>
      </div>
      <div className="edge-down e-2"><span>차단 대상일 때</span></div>
      <div className="node n-send">
        <span className="node-kind">COMMAND</span>
        <strong>원격 명령 전송</strong>
        <span>키 기반 SSH · BatchMode · 비밀번호 입력 없음</span>
      </div>
      <div className="edge-across e-ssh"><span>SSH 원격 명령</span><em>학교 LAN · 키 기반</em></div>
      <div className="node n-ufw">
        <span className="node-kind">ENFORCE</span>
        <strong>UFW deny 22/tcp</strong>
        <span className="mono">sudo -n ufw prepend deny proto tcp from &lt;공격 IP&gt; to any port 22</span>
      </div>
      <div className="edge-down e-3"><span>UFW 규칙 확인 · 실행 기록과 분리</span></div>
      <div className="node n-verify">
        <span className="node-kind">VERIFY</span>
        <strong>효과 검증</strong>
        <span>UFW 규칙 존재 AND 동일 Kali SSH 재접속 실패일 때만 성공</span>
      </div>
      <div className="node n-kali">
        <strong>SSH 재접속 시도</strong>
        <span>같은 공격 환경에서 접속 실패를 관찰해 기록</span>
      </div>
      <div className="edge-across e-kali"><span>SSH 재접속 시도</span><em>실패 여부 관찰</em></div>
    </div>
  );
}

function ResponseDetail({ id }) {
  const detail = useApi(id ? `/api/responses/${id}/` : null);
  if (!id) return <div className="state">목록에서 대응 기록을 선택하세요.</div>;
  const r = detail.data;
  if (!r) return <Status state={detail} />;
  const v = r.verification;
  return (
    <article className="response-record">
      <span className="kicker">대응 기록 #{r.id} · {r.action === 'block_ssh' ? 'SSH(22/tcp) 접근 차단' : r.action}</span>
      <h2 className="dossier-ip mono">{r.target_ip ?? '-'}</h2>
      <dl className="margin-facts">
        <div><dt>발동 경보</dt><dd className="inline-set"><IdLinks ids={[r.triggering_alert_id]} screen="alerts" prefix="경보 #" /> {ruleLabel(r.triggering_alert.rule_type)} <span className="mono muted">{formatTime(r.triggering_alert.occurred_at)}</span></dd></div>
        <div><dt>허용 목록</dt><dd>{ALLOWLIST[r.allowlist_result]} <span className="sub">{r.allowlist_detail}</span></dd></div>
      </dl>

      <h3 className="label">1 · 실행 결과</h3>
      <dl className="margin-facts">
        <div><dt>실행 상태</dt><dd><ExecutionBadge status={r.execution_status} /></dd></div>
        <div><dt>피해 서버</dt><dd className="mono">{r.victim || '-'}</dd></div>
        <div><dt>원격 명령</dt><dd className="mono">{r.command || '-'}</dd></div>
        <div><dt>실행 / 완료</dt><dd className="mono">{formatTime(r.executed_at)} / {formatTime(r.completed_at)}</dd></div>
        {r.failure_reason && <div><dt>실패·미실행 이유</dt><dd>{r.failure_reason}</dd></div>}
      </dl>
      {r.execution_result && <pre className="raw">{r.execution_result}</pre>}
      <p className="note">실행 성공은 UFW 명령이 성공했다는 뜻이며, 실제 차단 효과는 아래 검증으로 따로 판단합니다.</p>

      <h3 className="label">2 · 실제 효과 검증</h3>
      {!v ? (
        <p><strong className="tone-warning">미검증</strong> — 검증 기록이 없습니다. UFW 규칙 확인과 동일 Kali SSH 재접속 결과가 필요합니다.</p>
      ) : (
        <dl className="margin-facts">
          <div><dt>UFW 대상 IP 규칙</dt><dd><strong>{UFW[v.ufw_rule_result]}</strong><span className="sub">{v.ufw_check_evidence}</span></dd></div>
          <div><dt>동일 Kali 재접속</dt><dd><strong>{RECONNECT[v.kali_ssh_reconnect_result]}</strong><span className="sub">{v.reconnect_check_evidence}</span></dd></div>
          <div><dt>검증 시각</dt><dd className="mono">{formatTime(v.verified_at)}</dd></div>
          <div><dt>최종 판정</dt><dd><VerificationBadge record={r} /> <span className="muted">{VERIFY[v.verification_status]}</span>{r.verification_count > 1 && <span className="sub">검증 기록 {r.verification_count}건 중 최신</span>}</dd></div>
        </dl>
      )}
      <p className="note">검증 성공 = UFW 규칙 존재 AND 동일 Kali 재접속 실패. 자동 해제는 없으며 관리자가 수동 해제합니다.</p>
    </article>
  );
}

// SSH automatic response: a designed path with 0 execution records. Kept, but moved out of the way.
function SshAutoResponse({ selectedId }) {
  const responses = useApi('/api/responses/');
  const list = responses.data ?? [];
  const verified = list.some((r) => r.verification?.success);
  const empty = Array.isArray(responses.data) && list.length === 0;
  const count = responses.data ? list.length : responses.error ? '—' : '…';

  return (
    <details className="soar-ssh">
      <summary>
        SSH 자동 대응 상세 (설계 경로)
        <span className="sub">실행 기록 {count}{responses.data ? '건' : ''} · {verified ? '효과 검증 있음' : '미검증'}</span>
      </summary>

      <section className="response-main">
        <p className="screen-note">SSH 무차별 대입 경보 한 건이 세 장비를 거쳐 차단과 검증으로 이어지는 설계 경로입니다. 아래는 실행 기록이 아니라 개념도이며, 현재 SSH 자동 대응 실행 기록은 {count}건입니다.</p>
        <Architecture />
      </section>

      <aside className="response-rail">
        <dl className="status-rows">
          <div><dt>SSH 자동 대응</dt><dd className={list.length ? 'tone-success' : 'tone-warning'}>{list.length ? '실행 기록 있음' : '설계 경로 · 실행 기록 없음'}</dd></div>
          <div><dt>SSH 대응 기록</dt><dd>{count}{responses.data ? '건' : ''}</dd></div>
          <div><dt>SSH 실장비 효과 검증</dt><dd className={verified ? 'tone-success' : 'tone-warning'}>{verified ? '검증 성공 기록 있음' : '대기'}</dd></div>
        </dl>

        {empty ? (
          <div className="rail-text">
            <h2>아직 실제 SSH 자동 대응 실행 기록 없음</h2>
            <p>
              자동 분석 루프는 RESPONSE_EXECUTE가 활성화된 경우에만 SSH 대응을 실행합니다. 현재 SSH 경로는 외부 핫스팟에서
              피해 서버 22번에 직접 닿지 못해 실행 기록이 없습니다. 모의 결과는 표시하지 않습니다.
            </p>
          </div>
        ) : (
          <Status state={responses}>
            <ol className="index">
              {list.map((r) => (
                <li key={r.id} {...rowProps(() => go('response', r.id), r.id === selectedId)}>
                  <span className="index-title">대응 #{r.id} <span className="mono">{r.target_ip ?? '-'}</span></span>
                  <span className="index-meta"><ExecutionBadge status={r.execution_status} /> <VerificationBadge record={r} /></span>
                  <span className="index-meta mono">{formatTime(r.executed_at)} · 경보 #{r.triggering_alert_id}</span>
                </li>
              ))}
            </ol>
            <ResponseDetail id={selectedId} />
          </Status>
        )}
      </aside>
    </details>
  );
}

export default function ResponseStatus({ selectedId }) {
  return (
    <div className="response">
      <WebAutoConsole />
      <SshAutoResponse selectedId={selectedId} />
    </div>
  );
}
