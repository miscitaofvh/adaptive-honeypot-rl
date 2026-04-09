import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../App.jsx'

export default function Login() {
  const { login } = useAuth(); const navigate = useNavigate()
  const [form,setForm]=useState({username:'',password:''}); const [loading,setLoading]=useState(false); const [error,setError]=useState(null)
  const handleSubmit=async(e)=>{ e.preventDefault();setLoading(true);setError(null)
    try{ const d=await api.login(form.username,form.password); login(d.token,d.user); navigate('/') }
    catch(e){ setError(e.message||'Invalid credentials.') } finally{ setLoading(false) } }
  return (
    <main style={{ minHeight:'calc(100vh - 64px)', display:'flex', alignItems:'center', justifyContent:'center', padding:'40px 24px' }}>
      <div style={{ width:'100%', maxWidth:400, background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:'40px 36px' }} className="fade-up">
        <div style={{ marginBottom:32, textAlign:'center' }}>
          <p style={{ fontFamily:'var(--font-display)', fontWeight:700, fontSize:13, letterSpacing:'0.18em', color:'var(--accent)', marginBottom:14 }}>MERIDIAN</p>
          <h1 style={{ fontFamily:'var(--font-display)', fontSize:28, marginBottom:8 }}>Sign in</h1>
          <p style={{ fontSize:14, color:'var(--text-muted)' }}>Access member-only content and tools.</p>
        </div>
        <form onSubmit={handleSubmit} style={{ display:'flex', flexDirection:'column', gap:18 }}>
          <div>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:7 }}>Username</label>
            <input className="input" value={form.username} onChange={e=>setForm(f=>({...f,username:e.target.value}))} placeholder="your username" autoComplete="username" required/>
          </div>
          <div>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:7 }}>Password</label>
            <input className="input" type="password" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))} placeholder="••••••••" autoComplete="current-password" required/>
          </div>
          {error&&<p style={{ color:'#e06c75', fontSize:13, fontFamily:'var(--font-mono)', padding:'8px 12px', background:'rgba(224,108,117,0.08)', border:'1px solid rgba(224,108,117,0.2)', borderRadius:'var(--radius)' }}>{error}</p>}
          <button type="submit" className="btn btn-primary" style={{ width:'100%', justifyContent:'center', padding:11 }} disabled={loading}>
            {loading?<><span className="spinner" style={{width:14,height:14}}/> Signing in…</>:'Sign in'}
          </button>
        </form>
        <p style={{ marginTop:24, textAlign:'center', fontSize:13, color:'var(--text-muted)' }}>
          Don't have an account? <Link to="/" style={{ color:'var(--accent)' }}>Browse as guest</Link>
        </p>
      </div>
    </main>
  )
}
