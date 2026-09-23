import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('http://localhost:8000/health')
      .then(res => res.json())
      .then(data => {
        setHealth(data)
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setHealth({ status: 'unhealthy', error: 'Failed to connect to backend' })
        setLoading(false)
      })
  }, [])

  return (
    <div className="dashboard-container">
      <nav className="sidebar">
        <div className="logo">Threat Hunter</div>
        <ul className="nav-links">
          <li className="active">Dashboard</li>
          <li>Alerts</li>
          <li>Threat Hunting</li>
          <li>Hosts</li>
          <li>Incidents</li>
          <li>Investigation</li>
          <li>Reports</li>
        </ul>
      </nav>
      <main className="main-content">
        <header className="header">
          <h1>Dashboard</h1>
          <div className="status-indicator">
            Backend Status:{' '}
            {loading ? (
              <span className="status loading">Loading...</span>
            ) : (
              <span className={`status ${health?.status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                {health?.status === 'healthy' ? 'Healthy' : 'Unhealthy'}
              </span>
            )}
          </div>
        </header>
        <section className="content">
          <div className="card">
            <h2>Welcome to Network Threat Hunter</h2>
            <p>Phase 1 Foundation is ready.</p>
            {health && (
              <pre className="health-details">
                {JSON.stringify(health, null, 2)}
              </pre>
            )}
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
