import { Routes, Route, Link } from 'react-router-dom'
import Overview from './pages/Overview'
import Rules from './pages/Rules'
import Logs from './pages/Logs'

function App() {
  return (
    <div className="app">
      <aside className="sidebar">
        <h1>WAF</h1>
        <nav>
          <Link to="/">Overview</Link>
          <Link to="/rules">Rules</Link>
          <Link to="/logs">Logs</Link>
        </nav>
      </aside>
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/logs" element={<Logs />} />
        </Routes>
      </main>
    </div>
  )
}

export default App