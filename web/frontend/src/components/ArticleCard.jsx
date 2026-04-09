import { Link } from 'react-router-dom'

export default function ArticleCard({ article, featured = false }) {
  const date = new Date(article.created_at).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' })
  if (featured) return (
    <Link to={`/articles/${article.id}`} style={{ display:'block', padding:'40px 0', borderBottom:'1px solid var(--border)' }}>
      <div style={{ display:'flex', gap:14, marginBottom:16, alignItems:'center' }}>
        <span className="tag accent">{article.category}</span>
        <span style={{ fontSize:12, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{date}</span>
      </div>
      <h2 style={{ fontFamily:'var(--font-display)', fontSize:'clamp(26px,3vw,36px)', marginBottom:14, maxWidth:720 }}>{article.title}</h2>
      <p style={{ color:'var(--text-muted)', fontSize:16, lineHeight:1.7, maxWidth:640, marginBottom:20 }}>{article.summary}</p>
      <span style={{ fontSize:13, color:'var(--text-muted)' }}>by {article.author?.username} · {article.read_time} min read</span>
    </Link>
  )
  return (
    <Link to={`/articles/${article.id}`} style={{ display:'block', background:'var(--surface)',
      border:'1px solid var(--border-subtle)', borderRadius:'var(--radius)', padding:24 }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:14 }}>
        <span className="tag">{article.category}</span>
        <span style={{ fontSize:11, color:'var(--text-faint)', fontFamily:'var(--font-mono)' }}>{article.read_time} min</span>
      </div>
      <h3 style={{ fontSize:17, marginBottom:10, lineHeight:1.35 }}>{article.title}</h3>
      <p style={{ fontSize:13, color:'var(--text-muted)', lineHeight:1.65, marginBottom:18,
        display:'-webkit-box', WebkitLineClamp:3, WebkitBoxOrient:'vertical', overflow:'hidden' }}>{article.summary}</p>
      <div style={{ display:'flex', justifyContent:'space-between', paddingTop:14, borderTop:'1px solid var(--border-subtle)' }}>
        <span style={{ fontSize:12, color:'var(--text-muted)' }}>{article.author?.username}</span>
        <span style={{ fontSize:11, color:'var(--text-faint)', fontFamily:'var(--font-mono)' }}>{date}</span>
      </div>
    </Link>
  )
}
