import { useParams, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { api } from '../api/client.js'

export default function ArticleDetail() {
  const { id } = useParams()
  const [article, setArticle] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getArticle(parseInt(id))
      .then(setArticle)
      .catch(e => console.error(e))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <main style={{ padding: '48px 0' }}><div className="container">Loading...</div></main>
  if (!article) return <main><div className="container">Article not found</div></main>

  return (
    <main style={{ padding: '48px 0 80px' }}>
      <div className="container" style={{ maxWidth: 720 }}>
        <a href="/articles" style={{ color: 'var(--text-muted)' }}>← Back to Articles</a>
        <h1 style={{ marginTop: 24 }}>{article.title}</h1>
        <div style={{ display: 'flex', gap: 16, marginBottom: 32, color: 'var(--text-muted)', fontSize: 14 }}>
          <span>👤 {article.author?.username}</span>
          <span>📌 {article.category}</span>
          <span>⏱️ {article.read_time} min</span>
        </div>
        <div style={{ lineHeight: 1.8, color: 'var(--text)' }} dangerouslySetInnerHTML={{ __html: article.content || article.summary }} />
      </div>
    </main>
  )
}
