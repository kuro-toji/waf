import { useState, useEffect } from 'react'

interface Rule {
  id: string
  name: string
  severity: string
  enabled: boolean
  action: any
}

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/rules')
      .then(res => res.json())
      .then(data => {
        setRules(data)
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [])

  const toggleRule = async (id: string, enabled: boolean) => {
    // In a real app, this would call the API
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r))
  }

  if (loading) return <div>Loading...</div>

  return (
    <>
      <div className="header">
        <h2>Rules</h2>
        <button className="btn btn-primary">Add Rule</button>
      </div>

      <div className="chart-container">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>ID</th>
              <th>Severity</th>
              <th>Enabled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td>{rule.id}</td>
                <td>
                  <span className={`severity ${rule.severity}`}>{rule.severity}</span>
                </td>
                <td>
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={e => toggleRule(rule.id, e.target.checked)}
                  />
                </td>
                <td>
                  <button className="btn btn-danger">Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}