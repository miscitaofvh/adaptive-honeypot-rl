import { Link } from 'react-router-dom'
import { useAuth } from '../App.jsx'

export default function Navbar() {
  const { user, logout } = useAuth()
  const handleLogout = () => {
    logout()
  }

  return (
    <header>
      <nav className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Link to="/" style={{ fontWeight: 'bold', fontSize: 18 }}>🔒 Meridian</Link>
        <div style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
          <Link to="/">Home</Link>
          <Link to="/articles">Articles</Link>
          <Link to="/tools">Tools</Link>
          {user ? (
            <>
              <span style={{ color: 'var(--text-muted)' }}>👤 {user.username}</span>
              <button className="btn" onClick={handleLogout}>Logout</button>
            </>
          ) : (
            <Link to="/login">Login</Link>
          )}
        </div>
      </nav>
    </header>
  )
}
