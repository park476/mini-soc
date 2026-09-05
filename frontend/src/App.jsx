import React from 'react';
import EventTable from './components/EventTable';

function App() {
  return (
    <div>
      <header style={{ background: '#282c34', padding: '10px', color: 'white' }}>
        <h1>Mini SOC - Frontend Dashboard</h1>
      </header>
      <main>
        <EventTable />
      </main>
    </div>
  );
}

export default App;