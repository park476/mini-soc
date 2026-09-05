export const mockEvents = [
    {
        id: 1,
        timestamp: '2026-09-05 21:45:00',
        source_ip: "192.168.1.105",
        event_type : "SSH_BRUTE_FORCE",
        description: "Multiple login failures detected",
        severity: "High"
    },
    {
        id: 2,
        timestamp: '2026-09-05 22:00:00',
        source_ip: "10.0.0.42",
        event_type : "WEB_PATH_SCAN",
        description: "Multiple 404 errors on sensitive paths",
        severity: "Medium"
    }
];