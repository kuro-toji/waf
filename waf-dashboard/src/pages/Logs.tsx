import { useState, useEffect } from 'react'

interface Log {
  id: string
  timestamp: string
  client_ip: string
  attack_type: string
  severity: string
}

export default function Logs() {
  const [logs, setLogs] = useState<Log[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/logs?limit=50')
      .then(res => res.json())
      .then(data => {
        setLogs(data)
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [])

  if (loading) return <div>Loading...</div>

  return (
    <>
      <div className="header">
        <h2>Attack Logs</h2>
      </div>

      <div className="chart-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Client IP</th>
              <th>Attack Type</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {logs.map(log => (
              <tr key={log.id}>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td>{log.client_ip}</td>
                <td>{log.attack_type}</td>
                <td>
                  <span className={`severity ${log.severity}`}>{log.severity}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}