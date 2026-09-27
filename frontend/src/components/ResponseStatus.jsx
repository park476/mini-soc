import React from 'react';

// T5 is not implemented: this screen intentionally shows no response records.
export default function ResponseStatus() {
  return (
    <section className="panel">
      <div className="panel-head"><h2>자동 대응 결과 / 검증</h2></div>
      <p className="notice">
        <strong>상태: 자동 대응 구현 및 실장비 검증 예정</strong><br />
        현재 저장된 대응 기록이 없으며, 모의 결과를 표시하지 않습니다. 실제 IP 차단은 수행·검증되지 않았습니다.
      </p>
      <h4>구현 후 이 화면에 표시할 항목 (설계)</h4>
      <ol className="plan">
        <li>발동 경보: SSH 무차별 대입 Alert (상관분석·보안 사고를 기다리지 않음)</li>
        <li>허용 목록 판정: 관제 서버 등 관리 주소는 차단 제외</li>
        <li>실행 결과: 관제 서버 → 피해 서버 SSH 원격 실행, UFW 차단 명령의 성공/실패</li>
        <li>실제 효과 검증: UFW 차단 규칙 존재 확인 + 동일 Kali에서 SSH 재접속 실패 확인 — 둘 다 확인될 때만 검증 성공</li>
      </ol>
      <p className="note">실행 결과와 효과 검증은 별도로 저장·표시하며, 자동 해제는 없고 관리자가 수동 해제합니다.</p>
    </section>
  );
}
