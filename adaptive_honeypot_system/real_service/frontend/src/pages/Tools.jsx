import { useState } from 'react'
import { api } from '../api/client.js'

const TABS = ['Markdown Preview','Network Ping','URL Inspector']

export default function Tools() {
  const [tab, setTab] = useState(0)
  const tabStyle = (active) => ({ fontFamily:'var(--font-body)', fontSize:13, fontWeight:500,
    color:active?'var(--text)':'var(--text-muted)', padding:'10px 20px', background:'transparent',
    border:'none', borderBottom:active?'2px solid var(--accent)':'2px solid transparent',
    cursor:'pointer', marginBottom:-1 })
  return (
    <main style={{ padding:'48px 0 80px' }}>
      <div className="container">
        <div style={{ marginBottom:32 }}>
          <h1 style={{ fontFamily:'var(--font-display)', fontSize:36, marginBottom:6 }}>Developer Tools</h1>
          <p style={{ fontSize:14, color:'var(--text-muted)' }}>Utilities for debugging and inspection</p>
        </div>
        <div style={{ display:'flex', borderBottom:'1px solid var(--border)', marginBottom:32 }}>
          {TABS.map((t,i)=><button key={t} onClick={()=>setTab(i)} style={tabStyle(tab===i)}>{t}</button>)}
        </div>
        {tab===0&&<MarkdownPreview/>}{tab===1&&<PingTool/>}{tab===2&&<UrlInspector/>}
      </div>
    </main>
  )
}

function Label({children}) {
  return <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:8 }}>{children}</label>
}

function ErrMsg({msg}) {
  return msg ? <p style={{ color:'#e06c75', fontSize:13, marginTop:10, fontFamily:'var(--font-mono)' }}>{msg}</p> : null
}

function OutputBox({children}) {
  return <div style={{ marginTop:20, background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--radius)', overflow:'hidden' }}>{children}</div>
}

function Terminal({text,maxHeight=500}) {
  return <pre style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text)', padding:16, overflowX:'auto', whiteSpace:'pre-wrap', wordBreak:'break-all', lineHeight:1.6, maxHeight }}>{text}</pre>
}

function MarkdownPreview() {
  const [content,setContent] = useState('# Hello\n\nType some **Markdown** here.\n\n```python\nprint("hello")\n```')
  const [result,setResult] = useState(null); const [loading,setLoading] = useState(false); const [error,setError] = useState(null)
  const run = async()=>{ setLoading(true);setError(null); try{setResult(await api.preview(content))}catch(e){setError(e.message)}finally{setLoading(false)} }
  return (
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, alignItems:'start' }}>
      <div>
        <Label>Markdown Input</Label>
        <textarea className="textarea" style={{ minHeight:280, marginBottom:12 }} value={content} onChange={e=>setContent(e.target.value)}/>
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading?<><span className="spinner" style={{width:14,height:14}}/> Rendering…</>:'Render Preview'}</button>
        <ErrMsg msg={error}/>
      </div>
      <div>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
          <Label>Rendered Output</Label>
          {result&&<span style={{ fontSize:11, color:'var(--text-faint)', fontFamily:'var(--font-mono)' }}>{result.word_count} words · {result.read_time} min</span>}
        </div>
        <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:'20px 24px', minHeight:200, fontSize:15, lineHeight:1.7, overflowY:'auto', maxHeight:360 }}
          dangerouslySetInnerHTML={{ __html: result?.rendered||'<p style="color:var(--text-faint)">Preview appears here.</p>' }}/>
      </div>
    </div>
  )
}

function PingTool() {
  const [host,setHost]=useState(''); const [count,setCount]=useState(4)
  const [result,setResult]=useState(null); const [loading,setLoading]=useState(false); const [error,setError]=useState(null)
  const run=async()=>{ if(!host.trim())return; setLoading(true);setError(null); try{setResult(await api.ping(host.trim(),count))}catch(e){setError(e.message)}finally{setLoading(false)} }
  return (
    <div style={{ maxWidth:660 }}>
      <div style={{ display:'flex', gap:12, marginBottom:12 }}>
        <div style={{ flex:1 }}><Label>Hostname or IP</Label><input className="input" value={host} onChange={e=>setHost(e.target.value)} onKeyDown={e=>e.key==='Enter'&&run()} placeholder="e.g. 8.8.8.8"/></div>
        <div style={{ width:90 }}><Label>Packets</Label><input className="input" type="number" min={1} max={10} value={count} onChange={e=>setCount(Number(e.target.value))}/></div>
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading?<><span className="spinner" style={{width:14,height:14}}/> Pinging…</>:'Run Ping'}</button>
      <ErrMsg msg={error}/>
      {result&&<OutputBox>
        <div style={{ display:'flex', gap:20, padding:'10px 16px', borderBottom:'1px solid var(--border)', fontSize:12, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>
          <span>{result.host}</span>
          <span style={{ color:result.reachable?'#6fcf8a':'#e06c75' }}>{result.reachable?'● Reachable':'● Unreachable'}</span>
          {result.latency_ms !== null && result.latency_ms !== undefined && <span>{result.latency_ms.toFixed(2)} ms avg</span>}
        </div>
        <Terminal text={result.output}/>
      </OutputBox>}
    </div>
  )
}

function UrlInspector() {
  const [url,setUrl]=useState(''); const [result,setResult]=useState(null); const [loading,setLoading]=useState(false); const [error,setError]=useState(null)
  const run=async()=>{ if(!url.trim())return; setLoading(true);setError(null); try{setResult(await api.fetch(url.trim()))}catch(e){setError(e.message)}finally{setLoading(false)} }
  return (
    <div style={{ maxWidth:660 }}>
      <Label>URL</Label>
      <div style={{ display:'flex', gap:10, marginBottom:16 }}>
        <input className="input" value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&run()} placeholder="https://example.com"/>
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading?<span className="spinner" style={{width:14,height:14}}/>:'Fetch'}</button>
      </div>
      <ErrMsg msg={error}/>
      {result&&<OutputBox>
        <div style={{ display:'flex', borderBottom:'1px solid var(--border)' }}>
          {[['Status',result.status_code],['Type',result.content_type?.split(';')[0]],['Size',`${(result.size_bytes/1024).toFixed(1)} KB`],['Time',`${result.time_ms} ms`]].map(([k,v])=>(
            <div key={k} style={{ display:'flex', flexDirection:'column', padding:'10px 16px', borderRight:'1px solid var(--border)' }}>
              <span style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-faint)', letterSpacing:'0.08em', textTransform:'uppercase', marginBottom:3 }}>{k}</span>
              <span style={{ fontSize:14, fontFamily:'var(--font-mono)' }}>{v}</span>
            </div>
          ))}
        </div>
        <Terminal text={result.content?.slice(0,4000)+(result.content?.length>4000?'\n…(truncated)':'')} maxHeight={320}/>
      </OutputBox>}
    </div>
  )
}
