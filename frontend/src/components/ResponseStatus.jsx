import React from 'react';
import { formatTime, go, rowProps, ruleLabel, useApi, VERIFY } from '../api';
import Status, { ExecutionBadge, IdLinks, VerificationBadge } from './Status';

const ALLOWLIST = { excluded: '차단 제외 (허용 목록)', not_excluded: '제외 아님', unknown: '확인 불가' };
const UFW = { present: '규칙 존재 확인', absent: '규칙 없음', unchecked: '미확인' };
const RECONNECT = { failed: '접속 실패 확인', succeeded: '접속 성공 (차단 안 됨)', unchecked: '미확인' };

// Designed response path across the three machines (docs 05 §4). Not an execution record.
function Architecture() {
  return (
    <div className="arch" role="img" aria-label="자동 대응 설계 경로: 관제 서버에서 SSH로 피해 Ubuntu의 UFW를 제어하고, 피해 Ubuntu와 공격자 Kali에서 효과를 검증">
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

export default function ResponseStatus({ selectedId }) {
  const responses = useApi('/api/responses/');
  const list = responses.data ?? [];
  const verified = list.some((r) => r.verification?.success);
  const empty = Array.isArray(responses.data) && list.length === 0;
  const count = responses.data ? list.length : responses.error ? '—' : '…';

  return (
    <div className="response">
      <section className="response-main">
        <h1 className="screen-title">자동 대응 경로</h1>
        <p className="screen-note">SSH 무차별 대입 경보 한 건이 세 장비를 거쳐 차단과 검증으로 이어지는 설계 경로입니다. 실행 기록이 아닙니다.</p>
        <Architecture />
      </section>

      <aside className="response-rail">
        <dl className="status-rows">
          <div><dt>자동 대응 코드</dt><dd className="tone-success">구현 완료</dd></div>
          <div><dt>대응 기록</dt><dd>{count}{responses.data ? '건' : ''}</dd></div>
          <div><dt>실장비 효과 검증</dt><dd className={verified ? 'tone-success' : 'tone-warning'}>{verified ? '검증 성공 기록 있음' : '대기'}</dd></div>
        </dl>

        {empty ? (
          <div className="rail-text">
            <h2>아직 실제 자동 대응 실행 기록 없음</h2>
            <p>
              피해 Ubuntu 실장비 검증 전입니다. 자동 분석 루프는 RESPONSE_EXECUTE가 활성화된 경우에만 대응을 실행하므로
              현재는 대응 기록이 생성되지 않았습니다. 모의 결과는 표시하지 않습니다.
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

      <section className="criteria" aria-labelledby="criteria-title">
        <div className="criteria-head">
          <h2 id="criteria-title" className="kicker">EFFECT VERIFICATION · 효과 검증 기준</h2>
          <p><strong>실행 성공 ≠ 효과 검증 성공</strong> — UFW 명령이 성공해도 아래 두 조건이 모두 확인되기 전에는 검증 성공이 아닙니다.</p>
        </div>
        <div className="criteria-eq">
          <div className="criterion">
            <span className="criterion-where">피해 Ubuntu</span>
            <strong>UFW에 대상 IP 차단 규칙 존재</strong>
            <span className="mono">ufw status · 22/tcp DENY &lt;공격 IP&gt;</span>
          </div>
          <span className="criteria-op">AND</span>
          <div className="criterion">
            <span className="criterion-where">공격자 Kali</span>
            <strong>동일 환경의 SSH 재접속 실패</strong>
            <span>실제 재접속 결과를 관찰해 기록</span>
          </div>
          <span className="criteria-op">=</span>
          <div className={`criteria-result ${verified ? 'is-verified' : 'is-pending'}`}>
            <span className="criterion-where">현재 상태</span>
            <strong>{verified ? 'VERIFIED' : 'PENDING'}</strong>
            <span>{verified ? '검증 성공 기록 있음' : '검증 기록 없음 · 실장비 검증 대기'}</span>
          </div>
        </div>
        <p className="note">둘 중 하나라도 반대 결과가 확인되면 검증 실패, 확인되지 않은 조건이 있으면 미검증으로 기록합니다.</p>
      </section>
    </div>
  );
}
