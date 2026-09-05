import React from 'react';
import { mockEvents } from '../mockEvents';

export default function EventTable() {
  return (
    <div style={{ padding: '20px' }}>
      <h2>Security Event Table</h2>
      <table border="1" cellPadding="10" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: '#f4f4f4' }}>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Event Type</th>
            <th>Description</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {mockEvents.map((event) => (
            <tr key={event.id}>
              <td>{event.id}</td>
              <td>{event.timestamp}</td>
              <td>{event.source_ip}</td>
              <td>{event.event_type}</td>
              <td>{event.description}</td>
              <td>{event.severity}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}