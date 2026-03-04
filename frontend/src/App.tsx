import { useState, useEffect, useCallback, useRef } from 'react'

const API = '/api/v1'
const fmt = (b:number) => { if(!b) return '0 B'; const k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(1))+' '+s[i] }
const fnum = (n:number) => n ? n.toLocaleString() : '0'
const ago = (d:string) => { if(!d) return '—'; const s=Math.floor((Date.now()-new Date(d).getTime())/1000); if(s<60) return s+'s ago'; if(s<3600) return Math.floor(s/60)+'m ago'; if(s<86400) return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago' }
const PC:any = { aws:{bg:'#ff9900',t:'#000'}, azure:{bg:'#0078d4',t:'#fff'}, gcp:{bg:'#4285f4',t:'#fff'}, digitalocean:{bg:'#0080ff',t:'#fff'}, alibaba:{bg:'#ff6a00',t:'#fff'} }
const PL:any = { aws:'AWS S3', azure:'Azure Blob', gcp:'GCP Storage', digitalocean:'DO Spaces', alibaba:'Alibaba OSS' }
const EI:any = { sql:'🗄️',csv:'📊',json:'📋',yaml:'⚙️',yml:'⚙️',xml:'📄',pdf:'📕',docx:'📘',xlsx:'📗',zip:'📦',gz:'📦',env:'🔑',key:'🔐',pem:'🔐',pub:'🔐',sh:'🖥️',py:'🐍',js:'📜',css:'🎨',html:'🌐',log:'📝',md:'📝',ini:'⚙️',tfstate:'🏗️',bak:'💾',sqlite:'🗄️',parquet:'📊',php:'🐘' }

const apiFetch = async (ep:string, opts:any={}) => { try { const r=await fetch(`${API}${ep}`,{...opts,headers:{'Content-Type':'application/json',...opts.headers}}); if(!r.ok) throw 0; return await r.json() } catch{return null} }

const Badge = ({provider,big}:{provider:string,big?:boolean}) => { const c=PC[provider]||{bg:'#555',t:'#fff'}; return <span style={{background:c.bg,color:c.t,padding:big?'3px 10px':'1px 6px',borderRadius:3,fontSize:big?12:10,fontWeight:600,fontFamily:'var(--font-mono)',letterSpacing:'0.3px',whiteSpace:'nowrap'}}>{PL[provider]||provider}</span> }

const SBadge = ({s}:{s:string}) => { const m:any={open:{bg:'#00e87b18',b:'#00e87b',c:'#00e87b',l:'OPEN'},closed:{bg:'#f0484818',b:'#f04848',c:'#f04848',l:'CLOSED'},partial:{bg:'#f5a62318',b:'#f5a623',c:'#f5a623',l:'PARTIAL'}}; const v=m[s]||m.closed; return <span style={{background:v.bg,border:`1px solid ${v.b}`,color:v.c,padding:'1px 8px',borderRadius:3,fontSize:10,fontWeight:700,fontFamily:'var(--font-mono)',letterSpacing:'1px'}}>{v.l}</span> }

const Spin = () => <div style={{display:'flex',justifyContent:'center',padding:40}}><div style={{width:32,height:32,border:'3px solid var(--border-default)',borderTop:'3px solid var(--accent)',borderRadius:'50%',animation:'spin 0.8s linear infinite'}}/></div>

/* ════ LIVE SCAN PANEL ════ */
const LiveScanPanel = ({progress,events}:{progress:any,events:any[]}) => {
  if(!progress && events.length===0) return null
  const p = progress || {}
  const pct = p.names_total ? Math.round((p.names_checked/p.names_total)*100) : 0
  return (
    <div style={{background:'var(--bg-secondary)',border:'1px solid var(--accent)',borderRadius:'var(--radius-lg)',padding:20,marginBottom:24,animation:'glow 3s ease-in-out infinite'}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          <div style={{width:8,height:8,borderRadius:'50%',background:p.phase==='complete'?'var(--accent)':'var(--warning)',animation:p.phase==='scanning'?'pulse 1.5s infinite':'none'}}/>
          <span style={{fontSize:14,fontWeight:700,color:'var(--accent)'}}>LIVE SCAN {p.phase==='complete'?'COMPLETE':'IN PROGRESS'}</span>
          {p.provider && <Badge provider={p.provider}/>}
        </div>
        <span style={{fontSize:11,color:'var(--text-tertiary)'}}>{p.elapsed_ms?`${(p.elapsed_ms/1000).toFixed(1)}s`:''}</span>
      </div>
      {/* Progress bar */}
      <div style={{background:'var(--bg-primary)',borderRadius:4,height:6,marginBottom:12,overflow:'hidden'}}>
        <div style={{height:'100%',background:'linear-gradient(90deg,var(--accent),#00c568)',borderRadius:4,width:`${pct}%`,transition:'width 0.3s'}}/>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:12,fontSize:11,fontFamily:'var(--font-mono)'}}>
        {[['Checked',fnum(p.names_checked||0)+'/'+fnum(p.names_total||0)],['Found',fnum(p.buckets_found||0)],['Open',fnum(p.buckets_open||0)],['Files',fnum(p.files_indexed||0)],['Errors',fnum(p.errors||0)]].map(([l,v]:any)=>
          <div key={l} style={{textAlign:'center'}}><div style={{color:'var(--text-tertiary)',marginBottom:2}}>{l}</div><div style={{color:'var(--text-primary)',fontWeight:600}}>{v}</div></div>
        )}
      </div>
      {/* Recent discoveries */}
      {events.length>0 && <div style={{marginTop:12,maxHeight:150,overflow:'auto'}}>
        {events.slice(-8).reverse().map((e:any,i:number)=>(
          <div key={i} style={{display:'flex',alignItems:'center',gap:8,padding:'3px 0',fontSize:11,color:'var(--text-secondary)',animation:'fadeIn 0.3s'}}>
            <span style={{color:e.bucket?.status==='open'?'var(--accent)':'var(--text-tertiary)'}}>●</span>
            <Badge provider={e.bucket?.provider||'aws'}/>
            <span style={{color:'var(--accent)'}}>{e.bucket?.name}</span>
            <span style={{color:'var(--text-muted)'}}>—</span>
            <SBadge s={e.bucket?.status||'unknown'}/>
            {e.bucket?.file_count>0 && <span style={{color:'var(--text-tertiary)'}}>{e.bucket.file_count} files</span>}
          </div>
        ))}
      </div>}
    </div>
  )
}

/* ════ MAIN APP ════ */
export default function App() {
  const [view,setView] = useState('home')
  const [stats,setStats] = useState<any>(null)
  const [sq,setSq] = useState('')
  const [sr,setSr] = useState<any>(null)
  const [sLoading,setSLoading] = useState(false)
  const [sf,setSf] = useState({ext:'',provider:'',sort:'relevance',page:1})
  const [buckets,setBuckets] = useState<any>(null)
  const [bd,setBd] = useState<any>(null)
  const [scanForm,setScanForm] = useState({keywords:'',companies:'',providers:[] as string[]})
  const [scanStatus,setScanStatus] = useState<any>(null)
  const [scanProgress,setScanProgress] = useState<any>(null)
  const [scanEvents,setScanEvents] = useState<any[]>([])
  const [heroQ,setHeroQ] = useState('')
  const [sseConnected,setSseConnected] = useState(false)
  const ref = useRef<HTMLInputElement>(null)
  const sseCleanup = useRef<(()=>void)|null>(null)

  useEffect(() => { apiFetch('/stats').then(d => setStats(d)) }, [])

  // SSE subscription for live scan events
  const connectSSE = useCallback(() => {
    if(sseCleanup.current) sseCleanup.current()
    const es = new EventSource(`${API}/events/scans`)
    es.addEventListener('connected',() => setSseConnected(true))
    es.addEventListener('progress',(e:any) => setScanProgress(JSON.parse(e.data)))
    es.addEventListener('bucket_found',(e:any) => { const d=JSON.parse(e.data); setScanEvents(prev=>[...prev,d]) })
    es.addEventListener('scan_complete',(e:any) => { const d=JSON.parse(e.data); setScanProgress((p:any)=>({...p,...d.stats,phase:'complete'})) })
    es.addEventListener('scan_started',(e:any) => { setScanEvents([]); setScanProgress({phase:'scanning',...JSON.parse(e.data)}) })
    es.onerror = () => setSseConnected(false)
    sseCleanup.current = () => es.close()
    return () => es.close()
  },[])

  const doSearch = useCallback(async(q:string, f:any=sf) => {
    if(!q.trim()) return; setSLoading(true); setView('search'); setSq(q)
    const p:any = {q,...f}; Object.keys(p).forEach((k:string)=>!p[k]&&delete p[k])
    const qs = new URLSearchParams(p).toString()
    const d = await apiFetch(`/files?${qs}`)
    setSr(d || {items:[],total:0,page:1,per_page:50,query:q,response_time_ms:0})
    setSLoading(false)
  },[sf])

  const loadBk = useCallback(async(f:any={}) => {
    const qs=new URLSearchParams(f).toString()
    setBuckets(await apiFetch(`/buckets?${qs}`) || {items:[],total:0,page:1})
    setView('buckets')
  },[])

  const loadBd = useCallback(async(id:number) => {
    setBd(await apiFetch(`/buckets/${id}`) || null)
    setView('bucket-detail')
  },[])

  const startScan = async() => {
    const d:any = {
      keywords: scanForm.keywords.split(',').map((s:string)=>s.trim()).filter(Boolean),
      companies: scanForm.companies.split(',').map((s:string)=>s.trim()).filter(Boolean),
    }
    if(scanForm.providers.length) d.providers = scanForm.providers
    if(!d.keywords.length && !d.companies.length) return alert('Enter at least one keyword or company name')
    connectSSE()
    const r = await apiFetch('/scans',{method:'POST',body:JSON.stringify(d)})
    setScanStatus(r)
  }

  /* ─── NAV ─── */
  const Nav = () => (
    <nav style={{position:'fixed',top:0,left:0,right:0,zIndex:100,background:'linear-gradient(180deg,var(--bg-primary),rgba(6,10,16,0.92))',borderBottom:'1px solid var(--border-subtle)',backdropFilter:'blur(20px)',padding:'0 24px',height:56,display:'flex',alignItems:'center',gap:24}}>
      <div onClick={()=>setView('home')} style={{cursor:'pointer',display:'flex',alignItems:'center',gap:10}}>
        <div style={{width:28,height:28,borderRadius:6,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900}}>☁</div>
        <span style={{fontFamily:'var(--font-display)',fontWeight:700,fontSize:17,color:'var(--text-primary)',letterSpacing:'-0.5px'}}>Cloud<span style={{color:'var(--accent)'}}>Scan</span></span>
      </div>
      <div style={{display:'flex',gap:4}}>
        {([['search','Files','⌕'],['buckets','Buckets','◫'],['scan','Scanner','⟳'],['api-docs','API','{ }']]).map(([id,l,ic])=>(
          <button key={id} onClick={()=>{if(id==='buckets')loadBk();else if(id==='search'){setView('search');setTimeout(()=>ref.current?.focus(),100)}else setView(id as string)}}
            style={{background:view===id?'var(--bg-tertiary)':'transparent',border:view===id?'1px solid var(--border-default)':'1px solid transparent',color:view===id?'var(--accent)':'var(--text-tertiary)',
              padding:'6px 14px',borderRadius:'var(--radius-md)',cursor:'pointer',fontSize:13,fontFamily:'var(--font-mono)',transition:'all 0.15s'}}>
            <span style={{marginRight:5,fontSize:11}}>{ic}</span>{l}
          </button>))}
      </div>
      <div style={{flex:1}}/>
      {sseConnected && <div style={{display:'flex',alignItems:'center',gap:5,fontSize:10,color:'var(--accent)'}}>
        <div style={{width:6,height:6,borderRadius:'50%',background:'var(--accent)',animation:'pulse 2s infinite'}}/>LIVE
      </div>}
      {stats && <div style={{display:'flex',gap:20,fontSize:11,color:'var(--text-muted)'}}>
        <span>◫ {fnum(stats.total_buckets)}</span><span>⬡ {fnum(stats.total_files)}</span><span>⬢ {fmt(stats.total_size_bytes)}</span>
      </div>}
    </nav>
  )

  /* ─── HOME ─── */
  const Home = () => (
    <div style={{minHeight:'100vh',display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',background:'radial-gradient(ellipse 80% 50% at 50% -20%,#00e87b06 0%,transparent 60%),var(--bg-primary)',position:'relative',overflow:'hidden'}}>
      <div style={{position:'absolute',inset:0,opacity:0.025,backgroundImage:'linear-gradient(var(--accent) 1px,transparent 1px),linear-gradient(90deg,var(--accent) 1px,transparent 1px)',backgroundSize:'60px 60px'}}/>
      <div style={{position:'relative',textAlign:'center',maxWidth:800,padding:'0 24px'}}>
        {stats?.providers && <div style={{display:'flex',justifyContent:'center',gap:32,marginBottom:48}} className="fade-in">
          {stats.providers.map((p:any)=>(
            <div key={p.name} style={{textAlign:'center'}}>
              <div style={{fontSize:24,fontWeight:800,fontFamily:'var(--font-display)',color:PC[p.name]?.bg||'#fff'}}>{fnum(p.bucket_count)}</div>
              <div style={{fontSize:10,color:'var(--text-muted)',marginTop:2}}>{PL[p.name]||p.name}</div>
            </div>))}
        </div>}
        <h1 style={{fontSize:52,fontWeight:800,lineHeight:1.05,margin:'0 0 16px',fontFamily:'var(--font-display)',background:'linear-gradient(135deg,var(--text-primary) 0%,var(--text-secondary) 100%)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}} className="fade-in">
          Search Open<br/>Cloud Storage</h1>
        <p style={{fontSize:14,color:'var(--text-tertiary)',lineHeight:1.6,margin:'0 auto 40px',maxWidth:520}}>
          Discover exposed buckets & files across <span style={{color:'var(--aws)'}}>AWS</span>, <span style={{color:'var(--azure)'}}>Azure</span>, <span style={{color:'var(--gcp)'}}>GCP</span>, <span style={{color:'var(--digitalocean)'}}>DigitalOcean</span> & <span style={{color:'var(--alibaba)'}}>Alibaba</span>
        </p>
        <div style={{position:'relative',maxWidth:620,margin:'0 auto 24px'}} className="slide-up">
          <div style={{display:'flex',background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',overflow:'hidden',boxShadow:'0 0 40px var(--accent-glow),0 4px 24px rgba(0,0,0,0.4)'}}>
            <span style={{display:'flex',alignItems:'center',padding:'0 16px',color:'var(--text-muted)',fontSize:18}}>⌕</span>
            <input value={heroQ} onChange={e=>setHeroQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSearch(heroQ)}
              placeholder="Search files... (.env, backup.sql, credentials)" style={{flex:1,background:'none',border:'none',color:'var(--text-primary)',fontSize:15,padding:'16px 0',fontFamily:'var(--font-mono)'}}/>
            <button onClick={()=>doSearch(heroQ)} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',padding:'0 28px',cursor:'pointer',color:'#000',fontWeight:700,fontSize:13,fontFamily:'var(--font-mono)'}}>SEARCH</button>
          </div>
        </div>
        <div style={{display:'flex',gap:8,justifyContent:'center',flexWrap:'wrap'}}>
          {['.env','backup.sql','credentials.json','id_rsa','terraform.tfstate','.key','*.csv'].map(q=>(
            <button key={q} onClick={()=>{setHeroQ(q);doSearch(q)}}
              style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:'var(--radius-md)',padding:'5px 12px',color:'var(--text-tertiary)',fontSize:12,cursor:'pointer',fontFamily:'var(--font-mono)',transition:'all 0.15s'}}
              onMouseEnter={(e:any)=>{e.target.style.borderColor='var(--accent)';e.target.style.color='var(--accent)'}}
              onMouseLeave={(e:any)=>{e.target.style.borderColor='var(--border-subtle)';e.target.style.color='var(--text-tertiary)'}}>{q}</button>))}
        </div>
        {stats?.top_extensions && <div style={{marginTop:64,display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(85px,1fr))',gap:8,maxWidth:550,margin:'64px auto 0'}}>
          {stats.top_extensions.slice(0,12).map((e:any)=>(
            <div key={e.extension} onClick={()=>doSearch(`*.${e.extension}`)} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:'var(--radius-md)',padding:8,cursor:'pointer',textAlign:'center',transition:'all 0.15s'}}
              onMouseEnter={(ev:any)=>ev.currentTarget.style.borderColor='rgba(0,232,123,0.2)'} onMouseLeave={(ev:any)=>ev.currentTarget.style.borderColor='var(--border-subtle)'}>
              <span style={{fontSize:16}}>{EI[e.extension]||'📄'}</span>
              <div style={{fontSize:11,color:'var(--accent)',fontWeight:600}}>.{e.extension}</div>
              <div style={{fontSize:10,color:'var(--text-muted)'}}>{fnum(e.count)}</div>
            </div>))}
        </div>}
      </div>
    </div>
  )

  /* ─── SEARCH RESULTS ─── */
  const Search = () => (
    <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
      <LiveScanPanel progress={scanProgress} events={scanEvents}/>
      <div style={{display:'flex',gap:8,marginBottom:16,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',padding:'4px 4px 4px 16px',alignItems:'center'}}>
        <span style={{color:'var(--text-muted)',fontSize:16}}>⌕</span>
        <input ref={ref} value={sq} onChange={e=>setSq(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSearch(sq)}
          placeholder="Search files by name, path, extension..." style={{flex:1,background:'none',border:'none',color:'var(--text-primary)',fontSize:14,padding:'12px 0',fontFamily:'var(--font-mono)'}}/>
        <button onClick={()=>doSearch(sq)} style={{background:'var(--accent)',border:'none',padding:'8px 20px',borderRadius:'var(--radius-md)',cursor:'pointer',color:'#000',fontWeight:700,fontSize:12}}>SEARCH</button>
      </div>
      <div style={{display:'flex',gap:10,marginBottom:20,flexWrap:'wrap',alignItems:'center'}}>
        <select value={sf.provider} onChange={e=>{const f={...sf,provider:e.target.value,page:1};setSf(f);if(sq)doSearch(sq,f)}}
          style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-md)',color:'var(--text-secondary)',padding:'6px 12px',fontSize:12}}>
          <option value="">All Providers</option>{Object.entries(PL).map(([k,v])=><option key={k} value={k}>{v as string}</option>)}
        </select>
        <input value={sf.ext} onChange={e=>setSf({...sf,ext:e.target.value})} onKeyDown={e=>{if(e.key==='Enter')doSearch(sq,{...sf,ext:(e.target as any).value})}}
          placeholder="Extensions (csv,sql,json)" style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-md)',color:'var(--text-secondary)',padding:'6px 12px',fontSize:12,width:200}}/>
        <select value={sf.sort} onChange={e=>{const f={...sf,sort:e.target.value};setSf(f);if(sq)doSearch(sq,f)}}
          style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-md)',color:'var(--text-secondary)',padding:'6px 12px',fontSize:12}}>
          <option value="relevance">Relevance</option><option value="size_desc">Largest</option><option value="size_asc">Smallest</option><option value="newest">Newest</option><option value="filename">Filename</option>
        </select>
        {sr && <span style={{fontSize:11,color:'var(--text-muted)',marginLeft:'auto'}}>{fnum(sr.total)} results · {sr.response_time_ms}ms</span>}
      </div>
      {sLoading ? <Spin/> : sr?.items?.length ? <div style={{display:'flex',flexDirection:'column',gap:1}}>
        <div style={{display:'grid',gridTemplateColumns:'30px 1fr 95px 85px 75px 110px',gap:12,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}>
          <span/><span>File</span><span>Provider</span><span>Size</span><span>Age</span><span>Bucket</span>
        </div>
        {sr.items.map((f:any,i:number)=>(
          <div key={f.id||i} style={{display:'grid',gridTemplateColumns:'30px 1fr 95px 85px 75px 110px',gap:12,padding:'10px 16px',alignItems:'center',
            background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:'var(--radius-sm)',cursor:'pointer',transition:'background 0.1s'}}
            onMouseEnter={(e:any)=>e.currentTarget.style.background='var(--bg-hover)'} onMouseLeave={(e:any)=>e.currentTarget.style.background=i%2===0?'var(--bg-secondary)':'transparent'}>
            <span style={{fontSize:17,textAlign:'center'}}>{EI[f.extension]||'📄'}</span>
            <div style={{minWidth:0}}>
              <div style={{fontSize:13,whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}><a href={f.url} target="_blank" rel="noopener noreferrer" style={{color:'var(--accent-dim)'}}>{f.filename}</a></div>
              <div style={{fontSize:11,color:'var(--text-muted)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{f.filepath}</div>
            </div>
            <Badge provider={f.provider_name}/>
            <span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fmt(f.size_bytes)}</span>
            <span style={{fontSize:11,color:'var(--text-muted)'}}>{ago(f.last_modified)}</span>
            <span style={{fontSize:11,color:'var(--accent-dim)',cursor:'pointer',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}} onClick={(e:any)=>{e.stopPropagation();loadBd(f.bucket_id)}}>{f.bucket_name}</span>
          </div>))}
      </div> : sr ? <div style={{textAlign:'center',padding:60,color:'var(--text-muted)'}}>No results for "{sr.query}"</div>
        : <div style={{textAlign:'center',padding:60,color:'var(--text-muted)'}}>Enter a query to search exposed files across cloud storage</div>}
    </div>
  )

  /* ─── BUCKETS LIST ─── */
  const Buckets = () => (
    <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20,flexWrap:'wrap',gap:12}}>
        <h2 style={{fontSize:20,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>Public Buckets <span style={{fontSize:13,color:'var(--text-muted)',marginLeft:12}}>{fnum(buckets?.total||0)} indexed</span></h2>
        <div style={{display:'flex',gap:6}}>{['all','aws','azure','gcp','digitalocean','alibaba'].map(p=>(
          <button key={p} onClick={()=>loadBk(p==='all'?{}:{provider:p})} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:'var(--radius-md)',padding:'5px 12px',color:'var(--text-tertiary)',fontSize:11,cursor:'pointer'}}>{p==='all'?'All':PL[p]}</button>))}
        </div>
      </div>
      <div style={{display:'flex',flexDirection:'column',gap:2}}>
        <div style={{display:'grid',gridTemplateColumns:'1fr 95px 85px 75px 85px 85px 75px',gap:12,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}>
          <span>Bucket</span><span>Provider</span><span>Region</span><span>Status</span><span>Files</span><span>Size</span><span>Scanned</span>
        </div>
        {buckets?.items?.map((b:any,i:number)=>(
          <div key={b.id} onClick={()=>loadBd(b.id)} style={{display:'grid',gridTemplateColumns:'1fr 95px 85px 75px 85px 85px 75px',gap:12,padding:'12px 16px',alignItems:'center',cursor:'pointer',
            background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:'var(--radius-sm)',transition:'background 0.1s'}}
            onMouseEnter={(e:any)=>e.currentTarget.style.background='var(--bg-hover)'} onMouseLeave={(e:any)=>e.currentTarget.style.background=i%2===0?'var(--bg-secondary)':'transparent'}>
            <span style={{fontSize:14,color:'var(--accent-dim)',fontWeight:600}}>{b.name}</span>
            <Badge provider={b.provider_name}/><span style={{fontSize:12,color:'var(--text-muted)'}}>{b.region||'—'}</span>
            <SBadge s={b.status}/><span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fnum(b.file_count)}</span>
            <span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fmt(b.total_size_bytes)}</span>
            <span style={{fontSize:11,color:'var(--text-muted)'}}>{ago(b.last_scanned)}</span>
          </div>))}
      </div>
    </div>
  )

  /* ─── BUCKET DETAIL ─── */
  const BDetail = () => {
    if(!bd) return <Spin/>
    return (
      <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <button onClick={()=>setView('buckets')} style={{background:'none',border:'none',color:'var(--text-tertiary)',cursor:'pointer',fontSize:12,marginBottom:16,padding:0}}>← Back to buckets</button>
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',padding:24,marginBottom:24}}>
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:16,flexWrap:'wrap'}}>
            <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>{bd.name}</h2><Badge provider={bd.provider_name} big/><SBadge s={bd.status}/>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:16}}>
            {([['URL',bd.url],['Region',bd.region||'Global'],['Files',fnum(bd.file_count)],['Total Size',fmt(bd.total_size_bytes)],['First Seen',bd.first_seen?.split('T')[0]],['Last Scanned',ago(bd.last_scanned)]]).map(([l,v]:any)=>(
              <div key={l}><div style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase' as const,marginBottom:4}}>{l}</div><div style={{fontSize:13,color:'var(--text-secondary)',wordBreak:'break-all' as const}}>{v||'—'}</div></div>))}
          </div>
        </div>
        <h3 style={{fontSize:14,color:'var(--text-tertiary)',marginBottom:12}}>Contents ({fnum(bd.files?.total||0)} files)</h3>
        <div style={{display:'flex',flexDirection:'column',gap:1}}>
          {bd.files?.items?.map((f:any,i:number)=>(
            <div key={f.id||i} style={{display:'grid',gridTemplateColumns:'28px 1fr 85px 75px',gap:12,padding:'8px 12px',alignItems:'center',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:'var(--radius-sm)'}}>
              <span style={{fontSize:16}}>{EI[f.extension]||'📄'}</span>
              <a href={f.url} target="_blank" rel="noopener noreferrer" style={{fontSize:12,color:'var(--accent-dim)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{f.filepath}</a>
              <span style={{fontSize:11,color:'var(--text-muted)'}}>{fmt(f.size_bytes)}</span>
              <span style={{fontSize:10,color:'var(--text-muted)'}}>{ago(f.last_modified)}</span>
            </div>))}
        </div>
      </div>
    )
  }

  /* ─── SCANNER ─── */
  const Scanner = () => (
    <div style={{padding:'80px 24px 24px',maxWidth:800,margin:'0 auto'}}>
      <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Bucket Discovery Scanner</h2>
      <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24}}>Real-time scanning across all major cloud providers with live result streaming.</p>
      <LiveScanPanel progress={scanProgress} events={scanEvents}/>
      <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',padding:28}}>
        {([['KEYWORDS','keywords','backup, database, config, secret, credentials'] as const,['TARGET COMPANIES','companies','acme-corp, globex, initech'] as const]).map(([label,key,ph])=>(
          <div key={key} style={{marginBottom:20}}>
            <label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>{label} (comma-separated)</label>
            <input value={(scanForm as any)[key]} onChange={e=>setScanForm({...scanForm,[key]:e.target.value})} placeholder={ph}
              style={{width:'100%',boxSizing:'border-box' as const,background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:'var(--radius-md)',padding:'10px 14px',color:'var(--text-primary)',fontSize:13}}/>
          </div>))}
        <div style={{marginBottom:24}}>
          <label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:8}}>PROVIDERS</label>
          <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
            {Object.entries(PL).map(([k,l])=>{const a=scanForm.providers.includes(k);return(
              <button key={k} onClick={()=>setScanForm({...scanForm,providers:a?scanForm.providers.filter(p=>p!==k):[...scanForm.providers,k]})}
                style={{background:a?PC[k].bg+'20':'var(--bg-primary)',border:`1px solid ${a?PC[k].bg:'var(--border-subtle)'}`,borderRadius:'var(--radius-md)',padding:'6px 14px',cursor:'pointer',
                  color:a?PC[k].bg:'var(--text-muted)',fontSize:12,fontWeight:a?600:400}}>{l as string}</button>)})}
          </div>
        </div>
        <button onClick={startScan} disabled={scanProgress?.phase==='scanning'} style={{width:'100%',background:scanProgress?.phase==='scanning'?'var(--bg-tertiary)':'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:'var(--radius-md)',padding:14,
          color:scanProgress?.phase==='scanning'?'var(--text-tertiary)':'#000',fontWeight:700,fontSize:14,cursor:scanProgress?.phase==='scanning'?'not-allowed':'pointer',fontFamily:'var(--font-mono)'}}>
          {scanProgress?.phase==='scanning' ? '⟳ SCAN IN PROGRESS...' : '⟳ START DISCOVERY SCAN'}
        </button>
      </div>
    </div>
  )

  /* ─── API DOCS ─── */
  const ApiDocs = () => (
    <div style={{padding:'80px 24px 24px',maxWidth:900,margin:'0 auto'}}>
      <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>REST API Documentation</h2>
      <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:32}}>Authenticate with Bearer token or API key. Real-time scan events via SSE.</p>
      {[
        {m:'GET',p:'/api/v1/files',d:'Full-text search across indexed files',pr:'q, ext, exclude_ext, provider, bucket, sort, page, per_page, min_size, max_size'},
        {m:'GET',p:'/api/v1/buckets',d:'List discovered buckets with filters',pr:'provider, status, search, page, per_page'},
        {m:'GET',p:'/api/v1/buckets/:id',d:'Bucket details with paginated file listing',pr:'page, per_page'},
        {m:'GET',p:'/api/v1/stats',d:'Database statistics and top extensions',pr:'—'},
        {m:'GET',p:'/api/v1/events/scans',d:'Server-Sent Events for real-time scan progress',pr:'— (SSE stream)'},
        {m:'POST',p:'/api/v1/scans',d:'Start a discovery scan (streams results via SSE)',pr:'keywords[], companies[], providers[], max_names'},
        {m:'POST',p:'/api/v1/auth/register',d:'Create account, returns token + API key',pr:'email, username, password'},
        {m:'POST',p:'/api/v1/auth/login',d:'Login, returns JWT token',pr:'email, password'},
      ].map(ep=>(
        <div key={ep.p+ep.m} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',padding:20,marginBottom:12}}>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
            <span style={{background:ep.m==='GET'?'var(--accent-bg)':'#ff990015',color:ep.m==='GET'?'var(--accent)':'var(--aws)',
              padding:'2px 8px',borderRadius:'var(--radius-sm)',fontSize:11,fontWeight:700,border:`1px solid ${ep.m==='GET'?'rgba(0,232,123,0.2)':'rgba(255,153,0,0.2)'}`}}>{ep.m}</span>
            <span style={{fontSize:14,fontWeight:600}}>{ep.p}</span>
          </div>
          <div style={{fontSize:12,color:'var(--text-tertiary)',marginBottom:6}}>{ep.d}</div>
          <div style={{fontSize:11,color:'var(--text-muted)'}}>Params: {ep.pr}</div>
        </div>))}
      <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',padding:20,marginTop:24}}>
        <h3 style={{fontSize:14,marginBottom:12}}>Authentication</h3>
        <div style={{fontSize:12,color:'var(--text-tertiary)',lineHeight:1.8}}>
          <div>• <span style={{color:'var(--accent)'}}>Bearer Token:</span> Authorization: Bearer &lt;token&gt;</div>
          <div>• <span style={{color:'var(--accent)'}}>API Key Header:</span> X-API-Key: cs_xxx</div>
          <div>• <span style={{color:'var(--accent)'}}>API Key Param:</span> ?access_token=cs_xxx</div>
          <div>• <span style={{color:'var(--accent)'}}>SSE Stream:</span> EventSource('/api/v1/events/scans') — events: progress, bucket_found, scan_complete</div>
        </div>
      </div>
    </div>
  )

  return (
    <div style={{minHeight:'100vh',background:'var(--bg-primary)',color:'var(--text-primary)',fontFamily:'var(--font-mono)'}}>
      <Nav/>
      {view==='home' && <Home/>}
      {view==='search' && <Search/>}
      {view==='buckets' && <Buckets/>}
      {view==='bucket-detail' && <BDetail/>}
      {view==='scan' && <Scanner/>}
      {view==='api-docs' && <ApiDocs/>}
    </div>
  )
}
