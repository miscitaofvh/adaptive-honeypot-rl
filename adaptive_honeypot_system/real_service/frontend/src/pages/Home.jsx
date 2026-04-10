export default function Home() {
  return (
    <main style={{ padding: '60px 0 80px' }}>
      <div className="container">
        <h1>Welcome to Meridian</h1>
        <p style={{ fontSize: 18, color: 'var(--text-muted)', maxWidth: 600 }}>
          An adaptive security research platform that combines honeypots, machine learning, and reinforcement learning to analyze attacker behavior in real-time.
        </p>
        <div style={{ marginTop: 40, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 24 }}>
          <Card title="📚 Articles" desc="Learn about infrastructure, security, and performance patterns." />
          <Card title="🛠️ Tools" desc="Explore utilities for debugging and network inspection." />
          <Card title="🔐 Real-time Detection" desc="Integrated adaptive honeypots identify attack patterns." />
        </div>
      </div>
    </main>
  )
}

function Card({ title, desc }) {
  return (
    <div style={{ background: 'var(--surface)', padding: 24, borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
      <h3 style={{ marginTop: 0 }}>{title}</h3>
      <p style={{ color: 'var(--text-muted)', marginBottom: 0 }}>{desc}</p>
    </div>
  )
}
