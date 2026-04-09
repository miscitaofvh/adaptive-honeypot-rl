import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client.js'
import ArticleCard from '../components/ArticleCard.jsx'

const CATS = ['All','Infrastructure','Security','Architecture','Performance','Development']

export default function Articles() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [articles, setArticles] = useState([]); const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true); const [query, setQuery] = useState('')
  const category = searchParams.get('category') || 'All'

  const fetchArticles = useCallback(() => {
    setLoading(true)
    api.getArticles(1, category==='All'?'':category)
      .then(d=>{setArticles(d.articles||[]);setTotal(d.total||0)}).finally(()=>setLoading(false))
  }, [category])
  useEffect(()=>{fetchArticles()},[fetchArticles])

  const handleSearch = async (e) => {
    e.preventDefault(); if(!query.trim()) return fetchArticles()
    setLoading(true)
    try { const d = await api.searchArticles(query); setArticles(d.articles||[]); setTotal(d.total||0) }
    finally { setLoading(false) }
  }

  const fBtn = (active) => ({ fontFamily:'var(--font-body)', fontSize:12, fontWeight:500, padding:'5px 14px',
    borderRadius:2, border:'1px solid '+(active?'var(--accent)':'var(--border)'),
    color:active?'var(--accent)':'var(--text-muted)', background:active?'var(--accent-glow)':'transparent', cursor:'pointer' })

  return (
    <main style={{ padding:'48px 0 80px' }}>
      <div className="container">
        <div style={{ marginBottom:32 }}>
          <h1 style={{ fontFamily:'var(--font-display)', fontSize:36, marginBottom:6 }}>Articles</h1>
          <p style={{ fontSize:14, color:'var(--text-muted)' }}>{total} articles published</p>
        </div>
        <form onSubmit={handleSearch} style={{ display:'flex', gap:10, marginBottom:20, maxWidth:520 }}>
          <input className="input" style={{ flex:1 }} placeholder="Search articles…" value={query} onChange={e=>setQuery(e.target.value)}/>
          <button type="submit" className="btn btn-primary">Search</button>
        </form>
        <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
          {CATS.map(c=><button key={c} style={fBtn(category===c)} onClick={()=>{setQuery('');c==='All'?setSearchParams({}):setSearchParams({category:c})}}>{c}</button>)}
        </div>
        <div style={{ borderTop:'1px solid var(--border-subtle)', margin:'24px 0' }}/>
        {loading ? <div style={{ padding:'60px 0', display:'flex', justifyContent:'center' }}><span className="spinner"/></div>
          : articles.length===0 ? <p style={{ color:'var(--text-muted)' }}>No articles found{query?` for "${query}"`:''}</p>
          : <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(300px,1fr))', gap:16 }} className="fade-up">
              {articles.map(a=><ArticleCard key={a.id} article={a}/>)}
            </div>}
      </div>
    </main>
  )
}
