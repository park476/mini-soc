import React from 'react';
import { EXECUTION, formatTime, go, ruleLabel, useApi, VERIFY, verificationLabel } from '../api';
import Status from './Status';

const ALLOWLIST = { excluded: '차단 제외 (허용 목록)', not_excluded: '제외 아님', unknown: '확인 불가' };
const UFW = { present: '규칙 존재 확인', absent: '규칙 없음', unchecked: '미확인' };
const RECONNECT = { failed: '접속 실패 확인', succeeded: '접속 성공 (차단 안 됨)', unchecked: '미확인' };

function ResponseDetail({ id }) {
  const detail = useApi(id ? `/api/responses/${id}/` : null);
  if (!id) return <p className="state">목록에서 대응 기록을 선택하세요.</p>;
  const r = detail.data;
  if (!r) return <Status state={detail} />;
  const v = r.verification;
  return (
    <>
      <h3>대응 기록 #{r.id} · 대상 <span className="mono">{r.target_ip ?? '-'}</span></h3>
      <dl className="fields">
        <dt>발동 경보</dt>
        <dd>
          <button type="button" className="chip" onClick={() => go('alerts', r.triggering_alert_id)}>
            Alert #{r.triggering_alert_id}
          </button>{' '}
          {ruleLabel(r.triggering_alert.rule_type)} · {formatTime(r.triggering_alert.occurred_at)}
        </dd>
        <dt>대응 동작</dt><dd>{r.action === 'block_ssh' ? 'SSH(22/tcp) 접근 차단' : r.action}</dd>
        <dt>허용 목록 판정</dt><dd>{ALLOWLIST[r.allowlist_result]} <div className="muted wrap">{r.allowlist_detail}</div></dd>
      </dl>

      <h4>1. 실행 결과</h4>
      <dl className="fields">
        <dt>실행 상태</dt><dd><strong>{EXECUTION[r.execution_status]}</strong></dd>
        <dt>피해 서버</dt><dd className="mono">{r.victim || '-'}</dd>
        <dt>원격 명령</dt><dd className="mono wrap">{r.command || '-'}</dd>
        <dt>실행 / 완료</dt><dd className="mono">{formatTime(r.executed_at)} / {formatTime(r.completed_at)}</dd>
        {r.failure_reason && (<><dt>실패·미실행 이유</dt><dd className="wrap">{r.failure_reason}</dd></>)}
      </dl>
      {r.execution_result && <pre className="raw">{r.execution_result}</pre>}
      <p className="note">실행 성공은 UFW 명령이 성공했다는 뜻이며, 실제 차단 효과는 아래 검증으로 따로 판단합니다.</p>

      <h4>2. 실제 효과 검증</h4>
      {!v ? (
        <p className="notice"><strong>미검증</strong> — 검증 기록이 없습니다. UFW 규칙 확인과 동일 Kali SSH 재접속 결과가 필요합니다.</p>
      ) : (
        <>
          <ul className="checks">
            <li className={v.ufw_rule_present ? 'ok' : 'pending'}>UFW 대상 IP 차단 규칙: {UFW[v.ufw_rule_result]}</li>
            <li className={v.reconnect_failed ? 'ok' : 'pending'}>동일 Kali SSH 재접속: {RECONNECT[v.kali_ssh_reconnect_result]}</li>
          </ul>
          <dl className="fields">
            <dt>UFW 근거</dt><dd className="wrap small">{v.ufw_check_evidence}</dd>
            <dt>재접속 근거</dt><dd className="wrap small">{v.reconnect_check_evidence}</dd>
            <dt>검증 시각</dt><dd className="mono">{formatTime(v.verified_at)}</dd>
            <dt>최종 판정</dt><dd><strong>{VERIFY[v.verification_status]}</strong></dd>
          </dl>
          {r.verification_count > 1 && <p className="note">검증 기록 {r.verification_count}건 중 최신 기록입니다.</p>}
        </>
      )}
      <p className="note">검증 성공 = UFW 규칙 존재 AND 동일 Kali 재접속 실패. 자동 해제는 없으며 관리자가 수동 해제합니다.</p>
    </>
  );
}

export default function ResponseStatus({ selectedId }) {
  const responses = useApi('/api/responses/');
  const list = responses.data ?? [];
  const verified = list.some((r) => r.verification?.success);

  return (
    <>
      <p className="notice">
        <strong>상태: 자동 대응 코드 구현 완료 / {verified ? '실장비 효과 검증 기록 있음' : '실장비 효과 검증 대기'}</strong><br />
        SSH 무차별 대입 경보 → 허용 목록 검사 → 관제 서버에서 피해 서버로 SSH 원격 실행 → UFW로 공격 IP의 22/tcp 차단.
        상관분석·보안 사고를 기다리지 않습니다.
      </p>
      <div className="split">
        <section className="panel">
          <div className="panel-head"><h2>대응 기록 목록</h2></div>
          <Status state={responses} empty="아직 실제 자동 대응 실행 기록 없음">
            <table className="table clickable">
              <thead><tr><th>ID</th><th>대상 IP</th><th>발동 경보</th><th>실행 결과</th><th>실제 검증</th><th>실행 시각</th></tr></thead>
              <tbody>
                {list.map((r) => (
                  <tr key={r.id} className={r.id === selectedId ? 'selected' : ''} onClick={() => go('response', r.id)}>
                    <td>#{r.id}</td>
                    <td className="mono">{r.target_ip ?? '-'}</td>
                    <td>#{r.triggering_alert_id}</td>
                    <td>{EXECUTION[r.execution_status]}</td>
                    <td>{verificationLabel(r)}</td>
                    <td className="mono">{formatTime(r.executed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Status>
        </section>
        <section className="panel detail">
          <div className="panel-head"><h2>대응 상세</h2></div>
          <ResponseDetail id={selectedId} />
        </section>
      </div>
    </>
  );
}
