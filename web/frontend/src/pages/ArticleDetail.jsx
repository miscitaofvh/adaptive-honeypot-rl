import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../api/client.js'

export default function ArticleDetail() {
  const { id } = useParams()
  const [article, setArticle] = useState(null); const [loading, setLoading] = useState(true); const [error, setError] = useState(null)
  useEffect(()=>{ setLoading(true); api.getArticle(id).then(setArticle).catch(()=>setError('Article not found.')).finally(()=>setLoading(false)) },[id])

  if(loading) return <main style={{padding:'48px 0'}}><div className="container"><div style={{padding:'80px 0',display:'flex',justifyContent:'center'}}><span className="spinner"/></div></div></main>
  if(error||!article) return <main style={{padding:'48px 0'}}><div className="container"><p style={{color:'var(--text-muted)',marginBottom:16}}>{error}</p><Link to="/articles" style={{fontSize:12,fontFamily:'var(--font-mono)',color:'var(--text-muted)'}}>← Articles</Link></div></main>

  const date = new Date(article.created_at).toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'})
  return (
    <main style={{ padding:'36px 0 80px' }}>
      <div className="container">
        <Link to="/articles" style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-muted)', display:'inline-block', marginBottom:40 }}>← Articles</Link>
        <article style={{ maxWidth:720, margin:'0 auto' }} className="fade-up">
          <div style={{ display:'flex', gap:8, marginBottom:20, flexWrap:'wrap' }}>
            <span className="tag accent">{article.category}</span>
            {article.tags?.map(t=><span key={t} className="tag">{t}</span>)}
          </div>
          <h1 style={{ fontFamily:'var(--font-display)', fontSize:'clamp(28px,4vw,42px)', lineHeight:1.2, marginBottom:20 }}>{article.title}</h1>
          <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap', marginBottom:28 }}>
            <span style={{ fontSize:13, color:'var(--text-muted)' }}>by {article.author?.username}</span>
            <span style={{ color:'var(--text-faint)' }}>·</span>
            <span style={{ fontSize:12, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{date}</span>
            <span style={{ color:'var(--text-faint)' }}>·</span>
            <span style={{ fontSize:12, color:'var(--text-faint)', fontFamily:'var(--font-mono)' }}>{article.read_time} min read</span>
          </div>
          <div style={{ borderTop:'1px solid var(--border)', marginBottom:28 }}/>
          <p style={{ fontSize:18, color:'var(--text-muted)', lineHeight:1.75, fontStyle:'italic', fontFamily:'var(--font-display)', marginBottom:32 }}>{article.summary}</p>
          <div>
            {article.content?.split('\n\n').map((para,i)=>{
              if(para.startsWith('## ')) return <h2 key={i} style={{ fontFamily:'var(--font-display)', fontSize:24, marginTop:44, marginBottom:16 }}>{para.replace('## ','')}</h2>
              if(para.startsWith('### ')) return <h3 key={i} style={{ fontFamily:'var(--font-display)', fontSize:19, marginTop:32, marginBottom:12 }}>{para.replace('### ','')}</h3>
              if(para.startsWith('```')) return <pre key={i} style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:'18px 20px', overflow:'auto', marginBottom:24, fontSize:13, fontFamily:'var(--font-mono)', lineHeight:1.6 }}><code>{para.replace(/^```\w*\n?/,'').replace(/\n?```$/,'')}</code></pre>
              if(para.startsWith('> ')) return <blockquote key={i} style={{ borderLeft:'3px solid var(--accent)', paddingLeft:20, color:'var(--text-muted)', fontFamily:'var(--font-display)', fontStyle:'italic', fontSize:18, marginBottom:22 }}>{para.replace('> ','')}</blockquote>
              return <p key={i} style={{ fontSize:16, lineHeight:1.8, marginBottom:22 }}>{para}</p>
            })}
          </div>
        </article>
      </div>
    </main>
  )
}
