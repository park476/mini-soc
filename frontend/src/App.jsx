import React, { useEffect, useState } from 'react';
import AdminPanel from './components/AdminPanel';
import AlertsIncidents from './components/AlertsIncidents';
import Dashboard from './components/Dashboard';
import EventTable from './components/EventTable';
import ResponseStatus from './components/ResponseStatus';

// Hash routes keep direct URLs for capture, e.g. #/incidents/1, without a router dependency.
const TABS = [
  { key: 'dashboard', label: '관제 현황', routes: ['dashboard'] },
  { key: 'events', label: '보안 이벤트', routes: ['events'] },
  { key: 'alerts', label: '경보 · 사고', routes: ['alerts', 'incidents'] },
  { key: 'response', label: '자동 대응', routes: ['response'] },
  { key: 'admin', label: '관리자 패널', routes: ['admin'] },
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
        <div className="topbar-inner">
          <a className="brand" href="#/dashboard">
            <strong>소형 보안관제 시스템</strong>
          </a>
          <nav className="tabs" aria-label="화면 이동">
            {TABS.map((tab) => {
              const active = tab.routes.includes(screen);
              return (
                <a key={tab.key} href={`#/${tab.routes[0]}`} className={active ? 'tab active' : 'tab'}
                  aria-current={active ? 'page' : undefined}>
                  {tab.label}
                </a>
              );
            })}
          </nav>
        </div>
      </header>
      <main className="content">
        {screen === 'dashboard' && <Dashboard />}
        {screen === 'events' && <EventTable selectedId={id} />}
        {(screen === 'alerts' || screen === 'incidents') && <AlertsIncidents mode={screen} selectedId={id} />}
        {screen === 'response' && <ResponseStatus selectedId={id} />}
        {screen === 'admin' && <AdminPanel />}
      </main>
      <footer className="footer"><div className="footer-inner">시각은 KST(Asia/Seoul) 기준 · 데이터 출처: 관제 서버 Django API</div></footer>
    </div>
  );
}

export default App;
