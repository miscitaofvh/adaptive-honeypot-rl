import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../App.jsx'

export default function Navbar() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const isActive = (path) => location.pathname === path || location.pathname.startsWith(path + '/')
  const handleLogout = () => { logout(); navigate('/') }

  const nav = { position:'fixed', top:0, left:0, right:0, zIndex:100, height:64,
    background:'rgba(10,10,12,0.92)', backdropFilter:'blur(12px)', borderBottom:'1px solid var(--border-subtle)' }
  const inner = { maxWidth:'var(--max-w)', margin:'0 auto', padding:'0 32px', height:'100%',
    display:'flex', alignItems:'center', gap:40 }
  const logo = { fontFamily:'var(--font-display)', fontWeight:700, fontSize:18, letterSpacing:'0.14em', color:'var(--text)' }
  const link = (active) => ({ fontSize:13, color: active ? 'var(--text)' : 'var(--text-muted)',
    borderBottom: active ? '1px solid var(--accent)' : 'none', paddingBottom:2 })

  return (
    <nav style={nav}>
      <div style={inner}>
        <Link to="/" style={logo}>MERIDIAN</Link>
        <div style={{ display:'flex', gap:28, flex:1 }}>
          <Link to="/" style={link(location.pathname === '/')}>Home</Link>
          <Link to="/articles" style={link(isActive('/articles'))}>Articles</Link>
          <Link to="/tools" style={link(isActive('/tools'))}>Dev Tools</Link>
        </div>
        <div style={{ marginLeft:'auto' }}>
          {user ? (
            <div style={{ display:'flex', alignItems:'center', gap:16 }}>
              <span style={{ fontSize:13, color:'var(--text-muted)' }}>{user.username}</span>
              <button onClick={handleLogout} style={{ fontSize:13, color:'var(--text-muted)', cursor:'pointer' }}>Sign out</button>
            </div>
          ) : (
            <Link to="/login" className="btn btn-outline" style={{ fontSize:13 }}>Sign in</Link>
          )}
        </div>
      </div>
    </nav>
  )
}
