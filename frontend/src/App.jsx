import React, { useEffect, useState } from 'react';
import AlertsIncidents from './components/AlertsIncidents';
import Dashboard from './components/Dashboard';
import EventTable from './components/EventTable';
import ResponseStatus from './components/ResponseStatus';

// Hash routes keep direct URLs for capture, e.g. #/incidents/1, without a router dependency.
const TABS = [
  { key: 'dashboard', label: 'A 관제 대시보드', routes: ['dashboard'] },
  { key: 'events', label: 'B 보안 이벤트', routes: ['events'] },
  { key: 'alerts', label: 'C 경보 / 보안 사고', routes: ['alerts', 'incidents'] },
  { key: 'response', label: 'D 자동 대응', routes: ['response'] },
];
const ROUTES = TABS.flatMap((tab) => tab.routes);

function parseHash() {
  const [, screen, id] = window.location.hash.split('/');
  return {
    screen: ROUTES.includes(screen) ? screen : 'dashboard',
    id: id && /^\d+$/.test(id) ? Number(id) : null,
  };
}

function App() {
  const [route, setRoute] = useState(parseHash);

  useEffect(() => {
    const onChange = () => setRoute(parseHash());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const { screen, id } = route;
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>소형 보안관제 시스템</h1>
          <span className="subtitle">Nginx · SSH 로그 기반 탐지 · 상관분석 · 위험도</span>
        </div>
        <nav className="tabs" aria-label="화면 이동">
          {TABS.map((tab) => (
            <a
              key={tab.key}
              href={`#/${tab.routes[0]}`}
              className={tab.routes.includes(screen) ? 'tab active' : 'tab'}
            >
              {tab.label}
            </a>
          ))}
        </nav>
      </header>
      <main className="content">
        {screen === 'dashboard' && <Dashboard />}
        {screen === 'events' && <EventTable selectedId={id} />}
        {(screen === 'alerts' || screen === 'incidents') && <AlertsIncidents mode={screen} selectedId={id} />}
        {screen === 'response' && <ResponseStatus selectedId={id} />}
      </main>
      <footer className="footer">시각은 KST(Asia/Seoul) 기준 · 데이터 출처: 관제 서버 Django API</footer>
    </div>
  );
}

export default App;
