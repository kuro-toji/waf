import { useState, useEffect } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

interface Stats {
  total_requests: number
  blocked_requests: number
  allowed_requests: number
  block_rate: number
}

interface AttackStats {
  [key: string]: number
}

export default function Overview() {
  const [stats, setStats] = useState<Stats>({ total_requests: 0, blocked_requests: 0, allowed_requests: 0, block_rate: 0 })
  const [attacks, setAttacks] = useState<AttackStats>({})
  const [chartData, setChartData] = useState<any[]>([])

  useEffect(() => {
    // Fetch stats
    fetch('/api/stats')
      .then(res => res.json())
      .then(data => setStats(data))
      .catch(console.error)

    // Fetch attack stats
    fetch('/api/stats/attacks')
      .then(res => res.json())
      .then(data => setAttacks(data))
      .catch(console.error)

    // Simulate chart data
    const interval = setInterval(() => {
      setChartData(prev => {
        const newPoint = {
          time: new Date().toLocaleTimeString(),
          requests: Math.floor(Math.random() * 100),
          blocked: Math.floor(Math.random() * 10)
        }
        return [...prev.slice(-20), newPoint]
      })
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  return (
    <>
      <div className="header">
        <h2>Overview</h2>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">Total Requests</div>
          <div className="value">{stats.total_requests.toLocaleString()}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">Blocked</div>
          <div className="value">{stats.blocked_requests.toLocaleString()}</div>
        </div>
        <div className="stat-card success">
          <div className="label">Allowed</div>
          <div className="value">{stats.allowed_requests.toLocaleString()}</div>
        </div>
        <div className="stat-card warning">
          <div className="label">Block Rate</div>
          <div className="value">{(stats.block_rate * 100).toFixed(2)}%</div>
        </div>
      </div>

      <div className="chart-container">
        <h3>Request Rate</h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
            <XAxis dataKey="time" stroke="#666" />
            <YAxis stroke="#666" />
            <Tooltip />
            <Line type="monotone" dataKey="requests" stroke="#3b82f6" strokeWidth={2} />
            <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-container">
        <h3>Attack Breakdown</h3>
        <table>
          <thead>
            <tr>
              <th>Attack Type</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(attacks).map(([type, count]) => (
              <tr key={type}>
                <td>{type}</td>
                <td>{count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}