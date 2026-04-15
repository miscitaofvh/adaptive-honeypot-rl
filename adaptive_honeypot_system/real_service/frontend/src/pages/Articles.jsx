import { Link } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { api } from '../api/client.js'

export default function Articles() {
  const [articles, setArticles] = useState([])
  const [page, setPage] = useState(1)
  const [pages, setPages] = useState(1)

  useEffect(() => {
    api.getArticles(page).then(data => {
      const items = Array.isArray(data.items) ? data.items : []
      setArticles(items)
      setPages(Math.max(1, Number(data.pages) || 1))
    }).catch(e => console.error(e))
  }, [page])

  return (
    <main style={{ padding: '48px 0 80px' }}>
      <div className="container">
        <h1>Articles & Research</h1>
        <div style={{ display: 'grid', gap: 16 }}>
          {articles.map(a => (
            <ArticleCard key={a.id} article={a} />
          ))}
        </div>
        <div style={{ marginTop: 32, display: 'flex', gap: 10 }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>← Previous</button>
          <span style={{ padding: '8px 16px', color: 'var(--text-muted)' }}>Page {page} / {pages}</span>
          <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page >= pages}>Next →</button>
        </div>
      </div>
    </main>
  )
}

function ArticleCard({ article }) {
  return (
    <Link to={`/articles/${article.id}`} style={{ display: 'block', padding: 20, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', transition: 'all 0.2s', textDecoration: 'none', color: 'inherit' }}>
      <h3 style={{ marginTop: 0, color: 'var(--accent)' }}>{article.title}</h3>
      <p style={{ color: 'var(--text-muted)', marginBottom: 10 }}>{article.summary}</p>
      <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--text-faint)' }}>
        <span>👤 {article.author?.username}</span>
        <span>📌 {article.category}</span>
        <span>⏱️ {article.read_time} min</span>
      </div>
    </Link>
  )
}
