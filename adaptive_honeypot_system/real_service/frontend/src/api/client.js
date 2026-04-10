function ensureSessionId() {
  let sid = localStorage.getItem('sid')
  if (!sid) {
    sid = ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
      (c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16))
    localStorage.setItem('sid', sid)
  }
  document.cookie = `sid=${sid}; path=/; max-age=86400; SameSite=Lax`
  return sid
}
ensureSessionId()

async function request(path, options = {}) {
  const token = localStorage.getItem('token')
  const headers = { 'Content-Type': 'application/json', ...options.headers }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(path, { ...options, headers })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw { status: res.status, message: data.message || 'Request failed', data }
  return data
}

export const api = {
  login: (username, password) =>
    request('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => { localStorage.removeItem('token'); localStorage.removeItem('user') },
  getArticles: (page = 1, category = '') =>
    request(`/api/articles?page=${page}&limit=10${category ? `&category=${category}` : ''}`),
  getArticle: (id) => request(`/api/articles/${id}`),
  preview: (content) =>
    request('/api/tools/preview', { method: 'POST', body: JSON.stringify({ content }) }),
  ping: (host, count = 4) =>
    request('/api/tools/ping', { method: 'POST', body: JSON.stringify({ host, count }) }),
  fetch: (url) =>
    request('/api/tools/fetch', { method: 'POST', body: JSON.stringify({ url }) }),
}
