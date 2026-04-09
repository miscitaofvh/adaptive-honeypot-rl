import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import ArticleCard from '../components/ArticleCard.jsx'

const CATS = ['Infrastructure','Security','Architecture','Performance','Development']

export default function Home() {
  const [articles, setArticles] = useState([])
  const [loading, setLoading] = useState(true)
  useEffect(() => { api.getArticles(1).then(d => { setArticles(d.articles||[]); setLoading(false) }).catch(()=>setLoading(false)) }, [])
  const featured = articles[0]; const grid = articles.slice(1,7)
  return (
    <main>
      <section style={{ padding:'72px 0 48px', borderBottom:'1px solid var(--border-subtle)' }}>
        <div className="container">
          <p style={{ fontFamily:'var(--font-mono)', fontSize:11, letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--accent)', marginBottom:20 }}>Engineering Knowledge Base</p>
          <h1 style={{ fontFamily:'var(--font-display)', fontSize:'clamp(38px,5vw,62px)', fontWeight:600, lineHeight:1.1, marginBottom:22 }}>
            Deep dives into the craft<br/><em style={{ fontStyle:'italic', color:'var(--text-muted)' }}>of building software.</em>
          </h1>
          <p style={{ fontSize:17, color:'var(--text-muted)', maxWidth:500, lineHeight:1.7, marginBottom:40 }}>
            Practical guides, architecture patterns, and hard-won lessons from engineers in production.
          </p>
          <div style={{ display:'flex', flexWrap:'wrap', gap:8 }}>
            {CATS.map(c=><Link key={c} to={`/articles?category=${c}`} className="tag">{c}</Link>)}
          </div>
        </div>
      </section>
      <section style={{ padding:'56px 0' }}>
        <div className="container">
          <p style={{ fontFamily:'var(--font-mono)', fontSize:11, letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:4 }}>Featured</p>
          {loading ? <div style={{ padding:'40px 0', display:'flex', justifyContent:'center' }}><span className="spinner"/></div>
            : featured ? <ArticleCard article={featured} featured/> : null}
        </div>
      </section>
      <section style={{ padding:'56px 0' }}>
        <div className="container">
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end', marginBottom:24 }}>
            <p style={{ fontFamily:'var(--font-mono)', fontSize:11, letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--text-faint)' }}>Latest Articles</p>
            <Link to="/articles" style={{ fontSize:13, color:'var(--accent)' }}>View all →</Link>
          </div>
          {loading ? <div style={{ padding:'40px 0', display:'flex', justifyContent:'center' }}><span className="spinner"/></div>
            : <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(300px,1fr))', gap:16 }} className="fade-up">
                {grid.map(a=><ArticleCard key={a.id} article={a}/>)}
              </div>}
        </div>
      </section>
      <section style={{ borderTop:'1px solid var(--border-subtle)', padding:'40px 0', background:'var(--surface)' }}>
        <div className="container">
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:32 }}>
            <div>
              <h3 style={{ fontFamily:'var(--font-display)', fontSize:20, marginBottom:6 }}>Developer Tools</h3>
              <p style={{ fontSize:14, color:'var(--text-muted)' }}>Network diagnostics, Markdown preview, and URL inspection.</p>
            </div>
            <Link to="/tools" className="btn btn-outline">Open tools →</Link>
          </div>
        </div>
      </section>
    </main>
  )
}
