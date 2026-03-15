import { useState, useEffect, useCallback, useRef } from 'react'
import { API_BASE } from './config'

const API = API_BASE
const fmt = (b:number) => { if(!b) return '0 B'; const k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(1))+' '+s[i] }
const fnum = (n:number) => n ? n.toLocaleString() : '0'
const ago = (d:string) => { if(!d) return '—'; const s=Math.floor((Date.now()-new Date(d).getTime())/1000); if(s<60) return s+'s ago'; if(s<3600) return Math.floor(s/60)+'m ago'; if(s<86400) return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago' }
const PC:any = { aws:{bg:'#ff9900',t:'#000'}, azure:{bg:'#0078d4',t:'#fff'}, gcp:{bg:'#4285f4',t:'#fff'}, digitalocean:{bg:'#0080ff',t:'#fff'}, alibaba:{bg:'#ff6a00',t:'#fff'} }
const PL:any = { aws:'AWS S3', azure:'Azure Blob', gcp:'GCP Storage', digitalocean:'DO Spaces', alibaba:'Alibaba OSS' }
const EI:any = { sql:'🗄️',csv:'📊',json:'📋',yaml:'⚙️',yml:'⚙️',xml:'📄',pdf:'📕',docx:'📘',xlsx:'📗',zip:'📦',gz:'📦',env:'🔑',key:'🔐',pem:'🔐',pub:'🔐',sh:'🖥️',py:'🐍',js:'📜',css:'🎨',html:'🌐',log:'📝',md:'📝',ini:'⚙️',tfstate:'🏗️',bak:'💾',sqlite:'🗄️',parquet:'📊',php:'🐘' }
const IS = {width:'100%' as const,boxSizing:'border-box' as const,background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'10px 14px',color:'var(--text-primary)',fontSize:13,fontFamily:'var(--font-mono)'}

let _token: string | null = null
try { _token = localStorage.getItem('cs_token') } catch{}
const apiFetch = async (ep:string, opts:any={}) => {
  try {
    const headers: any = {'Content-Type':'application/json', ...opts.headers}
    if(_token) headers['Authorization'] = `Bearer ${_token}`
    const r = await fetch(`${API}${ep}`,{...opts, headers})
    if(r.status === 401) { _token = null; try{localStorage.removeItem('cs_token')}catch{} }
    if(!r.ok) { try { return await r.json() } catch { return null } }
    return await r.json()
  } catch{ return null }
}

// ── Stable components defined OUTSIDE App ──
const Badge = ({provider,big}:{provider:string,big?:boolean}) => { const c=PC[provider]||{bg:'#555',t:'#fff'}; return <span style={{background:c.bg,color:c.t,padding:big?'3px 10px':'1px 6px',borderRadius:3,fontSize:big?12:10,fontWeight:600,fontFamily:'var(--font-mono)',letterSpacing:'0.3px',whiteSpace:'nowrap'}}>{PL[provider]||provider}</span> }
const SBadge = ({s}:{s:string}) => { const m:any={open:{bg:'#00e87b18',b:'#00e87b',c:'#00e87b',l:'OPEN'},closed:{bg:'#f0484818',b:'#f04848',c:'#f04848',l:'CLOSED'},partial:{bg:'#f5a62318',b:'#f5a623',c:'#f5a623',l:'PARTIAL'}}; const v=m[s]||m.closed; return <span style={{background:v.bg,border:`1px solid ${v.b}`,color:v.c,padding:'1px 8px',borderRadius:3,fontSize:10,fontWeight:700,fontFamily:'var(--font-mono)',letterSpacing:'1px'}}>{v.l}</span> }
const SevBadge = ({s}:{s:string}) => { const m:any={critical:{bg:'#f04848',c:'#fff'},high:{bg:'#ff6b35',c:'#fff'},medium:{bg:'#f5a623',c:'#000'},low:{bg:'#4a9eff',c:'#fff'},info:{bg:'#4a5f73',c:'#fff'}}; const v=m[s]||m.info; return <span style={{background:v.bg,color:v.c,padding:'1px 6px',borderRadius:3,fontSize:9,fontWeight:700,textTransform:'uppercase' as const,letterSpacing:'0.5px'}}>{s}</span> }
const Spin = () => <div style={{display:'flex',justifyContent:'center',padding:40}}><div style={{width:32,height:32,border:'3px solid var(--border-default)',borderTop:'3px solid var(--accent)',borderRadius:'50%',animation:'spin 0.8s linear infinite'}}/></div>
const CC:any = {credentials:{c:'#f04848',l:'CREDENTIALS'},pii:{c:'#ff6b35',l:'PII'},financial:{c:'#f5a623',l:'FINANCIAL'},medical:{c:'#e74c9e',l:'MEDICAL'},infrastructure:{c:'#4a9eff',l:'INFRA'},source_code:{c:'#9b59b6',l:'SOURCE'},database:{c:'#3498db',l:'DATABASE'},generic:{c:'#4a5f73',l:'GENERIC'}}
const ClassBadge = ({c}:{c:string}) => { const v=CC[c]||CC.generic; return <span style={{background:v.c+'18',color:v.c,border:`1px solid ${v.c}40`,padding:'1px 6px',borderRadius:3,fontSize:9,fontWeight:700,letterSpacing:'0.5px'}}>{v.l}</span> }
const RC:any = {critical:{bg:'#f04848',c:'#fff'},high:{bg:'#ff6b35',c:'#fff'},medium:{bg:'#f5a623',c:'#000'},low:{bg:'#4a9eff',c:'#fff'},info:{bg:'#4a5f73',c:'#fff'}}
const RiskBadge = ({score,level}:{score:number,level:string}) => { const v=RC[level]||RC.info; return <span style={{background:v.bg,color:v.c,padding:'2px 8px',borderRadius:4,fontSize:10,fontWeight:700,whiteSpace:'nowrap' as const}}>{score}/100 {level.toUpperCase()}</span> }

const LiveScanPanel = ({progress:p,events}:{progress:any,events:any[]}) => {
  if(!p && events.length===0) return null; p=p||{}
  const pct = p.names_total ? Math.round((p.names_checked/p.names_total)*100) : 0
  return <div style={{background:'var(--bg-secondary)',border:'1px solid var(--accent)',borderRadius:12,padding:20,marginBottom:24,animation:'glow 3s ease-in-out infinite'}}>
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
      <div style={{display:'flex',alignItems:'center',gap:8}}>
        <div style={{width:8,height:8,borderRadius:'50%',background:p.phase==='complete'?'var(--accent)':'var(--warning)',animation:p.phase==='scanning'?'pulse 1.5s infinite':'none'}}/>
        <span style={{fontSize:14,fontWeight:700,color:'var(--accent)'}}>LIVE SCAN {p.phase==='complete'?'COMPLETE':'IN PROGRESS'}</span>
        {p.provider && <Badge provider={p.provider}/>}</div>
      <span style={{fontSize:11,color:'var(--text-tertiary)'}}>{p.elapsed_ms?`${(p.elapsed_ms/1000).toFixed(1)}s`:''}</span></div>
    <div style={{background:'var(--bg-primary)',borderRadius:4,height:6,marginBottom:12,overflow:'hidden'}}><div style={{height:'100%',background:'linear-gradient(90deg,var(--accent),#00c568)',borderRadius:4,width:`${pct}%`,transition:'width 0.3s'}}/></div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:12,fontSize:11}}>
      {[['Checked',fnum(p.names_checked||0)+'/'+fnum(p.names_total||0)],['Found',fnum(p.buckets_found||0)],['Open',fnum(p.buckets_open||0)],['Files',fnum(p.files_indexed||0)],['Errors',fnum(p.errors||0)]].map(([l,v]:any)=>
        <div key={l} style={{textAlign:'center'}}><div style={{color:'var(--text-tertiary)',marginBottom:2}}>{l}</div><div style={{color:'var(--text-primary)',fontWeight:600}}>{v}</div></div>)}</div>
    {events.length>0 && <div style={{marginTop:12,maxHeight:150,overflow:'auto'}}>
      {events.slice(-8).reverse().map((e:any,i:number)=><div key={i} style={{display:'flex',alignItems:'center',gap:8,padding:'3px 0',fontSize:11,color:'var(--text-secondary)'}}>
        <span style={{color:e.bucket?.status==='open'?'var(--accent)':'var(--text-tertiary)'}}>●</span><Badge provider={e.bucket?.provider||'aws'}/><span style={{color:'var(--accent)'}}>{e.bucket?.name}</span><SBadge s={e.bucket?.status||'unknown'}/>
        {e.bucket?.file_count>0 && <span style={{color:'var(--text-tertiary)'}}>{e.bucket.file_count} files</span>}</div>)}</div>}
  </div>
}

/* ════ MAIN APP — all views inlined to avoid remount-on-rerender ════ */
export default function App() {
  const [view,setView] = useState('home')
  const [stats,setStats] = useState<any>(null)
  const [sq,setSq] = useState(''); const [sr,setSr] = useState<any>(null); const [sLoading,setSLoading] = useState(false)
  const [sf,setSf] = useState({ext:'',provider:'',sort:'relevance',page:1}); const [regexMode,setRegexMode] = useState(false)
  const [buckets,setBuckets] = useState<any>(null); const [bd,setBd] = useState<any>(null)
  const [savedSearches,setSavedSearches] = useState<any[]>([]); const [saveSearchName,setSaveSearchName] = useState(''); const [showSavedDropdown,setShowSavedDropdown] = useState(false)
  const [previewFile,setPreviewFile] = useState<number|null>(null); const [previewData,setPreviewData] = useState<any>(null); const [previewLoading,setPreviewLoading] = useState(false)
  const [dashTimeline,setDashTimeline] = useState<any>(null); const [dashBreakdown,setDashBreakdown] = useState<any>(null)
  const [scanForm,setScanForm] = useState({keywords:'',companies:'',providers:[] as string[]})
  const [scanStatus,setScanStatus] = useState<any>(null)
  const [scanProgress,setScanProgress] = useState<any>(null); const [scanEvents,setScanEvents] = useState<any[]>([])
  const [heroQ,setHeroQ] = useState(''); const [sseConnected,setSseConnected] = useState(false)
  const ref = useRef<HTMLInputElement>(null); const sseCleanup = useRef<(()=>void)|null>(null)
  const [user,setUser] = useState<any>(null)
  const [authMode,setAuthMode] = useState<'login'|'register'|'forgot'|'reset'>('login')
  const [authForm,setAuthForm] = useState({email:'',username:'',password:''})
  const [authError,setAuthError] = useState(''); const [authLoading,setAuthLoading] = useState(false)
  const [resetToken,setResetToken] = useState(''); const [authSuccess,setAuthSuccess] = useState('')
  const [watchlists,setWatchlists] = useState<any[]>([]); const [alerts,setAlerts] = useState<any>(null); const [monDash,setMonDash] = useState<any>(null)
  const [wlForm,setWlForm] = useState({name:'',keywords:'',companies:'',providers:[] as string[],interval:24})
  const [webhooks,setWebhooks] = useState<any[]>([]); const [whForm,setWhForm] = useState({name:'',url:'',secret:'',event_types:['critical','high'] as string[]})
  // AI state
  const [aiAvail,setAiAvail] = useState(false); const [nlMode,setNlMode] = useState(false); const [nlQuery,setNlQuery] = useState(''); const [nlParsed,setNlParsed] = useState<any>(null)
  const [aiReport,setAiReport] = useState<any>(null); const [aiReportLoading,setAiReportLoading] = useState(false)
  const [suggestedKw,setSuggestedKw] = useState<string[]>([]); const [suggestLoading,setSuggestLoading] = useState(false)
  const [aiClassSummary,setAiClassSummary] = useState<any>(null); const [classifyLoading,setClassifyLoading] = useState(false)
  const [aiProvider,setAiProvider] = useState(''); const [aiProviders,setAiProviders] = useState<any[]>([]); const [providerSwitching,setProviderSwitching] = useState(false)
  // Sprint 3 state
  const [theme,setTheme] = useState<'dark'|'light'>(()=>{ try{return(localStorage.getItem('cs_theme') as 'dark'|'light')||'dark'}catch{return 'dark'} })
  const [alertSevFilter,setAlertSevFilter] = useState('')
  const [scanHistory,setScanHistory] = useState<any[]>([]); const [scanHistoryLoading,setScanHistoryLoading] = useState(false)
  const [showApiKey,setShowApiKey] = useState(false); const [settingsForm,setSettingsForm] = useState({username:'',password:'',confirmPassword:''}); const [settingsMsg,setSettingsMsg] = useState('')
  const [activity,setActivity] = useState<any>(null); const [activityPage,setActivityPage] = useState(1)
  const [showWelcome,setShowWelcome] = useState(false); const [copiedKey,setCopiedKey] = useState(false)
  const [onboarding,setOnboarding] = useState<{firstScan:boolean,firstSearch:boolean,firstMonitor:boolean,dismissed:boolean}>(()=>{ try{const s=localStorage.getItem('cs_onboarding');return s?JSON.parse(s):{firstScan:false,firstSearch:false,firstMonitor:false,dismissed:false}}catch{return{firstScan:false,firstSearch:false,firstMonitor:false,dismissed:false}} })

  useEffect(()=>{ document.documentElement.setAttribute('data-theme',theme); try{localStorage.setItem('cs_theme',theme)}catch{} },[theme])
  useEffect(()=>{ try{localStorage.setItem('cs_onboarding',JSON.stringify(onboarding))}catch{} },[onboarding])

  useEffect(() => { apiFetch('/stats').then(d => setStats(d)); apiFetch('/ai/status').then(d => { if(d){setAiAvail(d.available||false);setAiProvider(d.active_provider||'');setAiProviders(d.providers||[])} }); apiFetch('/stats/timeline?days=30').then(d=>d&&setDashTimeline(d)); apiFetch('/stats/breakdown').then(d=>d&&setDashBreakdown(d)) }, [])
  useEffect(() => { if(_token) { apiFetch('/auth/me').then(d => { if(d?.id) setUser(d); else { _token=null; try{localStorage.removeItem('cs_token')}catch{} } }); apiFetch('/searches/saved').then(d=>{if(d?.items)setSavedSearches(d.items)}) } }, [])

  const connectSSE = useCallback(() => {
    if(sseCleanup.current) sseCleanup.current()
    const es = new EventSource(`${API}/events/scans`)
    es.addEventListener('connected',() => setSseConnected(true))
    es.addEventListener('progress',(e:any) => setScanProgress(JSON.parse(e.data)))
    es.addEventListener('bucket_found',(e:any) => { const d=JSON.parse(e.data); setScanEvents(prev=>[...prev,d]) })
    es.addEventListener('scan_complete',(e:any) => { const d=JSON.parse(e.data); setScanProgress((p:any)=>({...p,...d.stats,phase:'complete'})); apiFetch('/stats').then(d=>d&&setStats(d)) })
    es.addEventListener('scan_started',(e:any) => { setScanEvents([]); setScanProgress({phase:'scanning',...JSON.parse(e.data)}) })
    es.onerror = () => setSseConnected(false); sseCleanup.current = () => es.close(); return () => es.close()
  },[])
  useEffect(() => { const c = connectSSE(); return c }, [connectSSE])

  const doLogin = async() => { setAuthError(''); setAuthSuccess(''); setAuthLoading(true); const r = await apiFetch('/auth/login',{method:'POST',body:JSON.stringify({email:authForm.email,password:authForm.password})}); setAuthLoading(false); if(!r||!r.token){setAuthError(r?.error||'Invalid credentials');return}; _token=r.token; try{localStorage.setItem('cs_token',r.token)}catch{}; setUser(r.user); setView('home'); setAuthForm({email:'',username:'',password:''}) }
  const doRegister = async() => { setAuthError(''); setAuthSuccess(''); setAuthLoading(true); const r = await apiFetch('/auth/register',{method:'POST',body:JSON.stringify(authForm)}); setAuthLoading(false); if(!r||!r.token){setAuthError(r?.error||'Registration failed');return}; _token=r.token; try{localStorage.setItem('cs_token',r.token)}catch{}; setUser(r.user); setShowWelcome(true); setView('home'); setAuthForm({email:'',username:'',password:''}) }
  const doLogout = () => { _token=null; try{localStorage.removeItem('cs_token')}catch{}; setUser(null); setView('home'); setAuthMode('login'); setAuthError(''); setAuthSuccess('') }
  const doForgotPassword = async() => {
    setAuthError(''); setAuthSuccess(''); setAuthLoading(true)
    const r = await apiFetch('/auth/forgot-password',{method:'POST',body:JSON.stringify({email:authForm.email})})
    setAuthLoading(false)
    if(!r) { setAuthError('Request failed'); return }
    if(r.token) {
      setResetToken(r.token)
      setAuthSuccess('Reset token generated! Enter your new password below.')
      setAuthMode('reset')
    } else {
      setAuthSuccess(r.message || 'If that email exists, a reset link has been sent.')
    }
  }
  const doResetPassword = async() => {
    setAuthError(''); setAuthSuccess(''); setAuthLoading(true)
    const r = await apiFetch('/auth/reset-password',{method:'POST',body:JSON.stringify({token:resetToken,password:authForm.password})})
    setAuthLoading(false)
    if(!r||!r.token) { setAuthError(r?.error||'Reset failed'); return }
    _token=r.token; try{localStorage.setItem('cs_token',r.token)}catch{}
    setAuthSuccess('Password reset successfully! Logging you in...')
    setTimeout(async()=>{ const me=await apiFetch('/auth/me'); if(me?.id)setUser(me); setView('home'); setAuthForm({email:'',username:'',password:''}); setResetToken(''); setAuthSuccess('') },1500)
  }

  const loadMonitor = async() => { setView('monitor'); const [wl,al,dash,wh] = await Promise.all([apiFetch('/monitor/watchlists'),apiFetch('/monitor/alerts'),apiFetch('/monitor/dashboard'),apiFetch('/monitor/webhooks')]); if(wl?.items)setWatchlists(wl.items); if(al)setAlerts(al); if(dash)setMonDash(dash); if(wh?.items)setWebhooks(wh.items) }
  const createWatchlist = async() => { const kw=wlForm.keywords.split(',').map(s=>s.trim()).filter(Boolean); if(!wlForm.name||!kw.length)return; await apiFetch('/monitor/watchlists',{method:'POST',body:JSON.stringify({name:wlForm.name,keywords:kw,companies:wlForm.companies.split(',').map(s=>s.trim()).filter(Boolean),providers:wlForm.providers.length?wlForm.providers:undefined,scan_interval_hours:wlForm.interval})}); setWlForm({name:'',keywords:'',companies:'',providers:[],interval:24}); loadMonitor(); setOnboarding(o=>({...o,firstMonitor:true})) }
  const triggerWlScan = async(id:number) => { await apiFetch(`/monitor/watchlists/${id}/scan`,{method:'POST'}); loadMonitor() }
  const deleteWl = async(id:number) => { await apiFetch(`/monitor/watchlists/${id}`,{method:'DELETE'}); loadMonitor() }
  const markAlertRead = async(id:number) => { await apiFetch(`/monitor/alerts/${id}/read`,{method:'POST'}); loadMonitor() }
  const createWebhook = async() => { if(!whForm.name||!whForm.url)return; await apiFetch('/monitor/webhooks',{method:'POST',body:JSON.stringify(whForm)}); setWhForm({name:'',url:'',secret:'',event_types:['critical','high']}); loadMonitor() }
  const deleteWebhook = async(id:number) => { await apiFetch(`/monitor/webhooks/${id}`,{method:'DELETE'}); loadMonitor() }
  const toggleWebhook = async(id:number, active:boolean) => { await apiFetch(`/monitor/webhooks/${id}`,{method:'PUT',body:JSON.stringify({is_active:active?1:0})}); loadMonitor() }
  const testWebhook = async(id:number) => { const r = await apiFetch(`/monitor/webhooks/${id}/test`,{method:'POST'}); if(r?.success) alert('Webhook test sent successfully!'); else alert('Webhook test failed: '+(r?.error||'Unknown error')) }
  const doSaveSearch = async() => { if(!saveSearchName.trim()||!sq.trim())return; const params:any={q:regexMode?'':sq,regex:regexMode?sq:'',ext:sf.ext,provider:sf.provider,sort:sf.sort,regexMode}; await apiFetch('/searches/saved',{method:'POST',body:JSON.stringify({name:saveSearchName,query_params:params})}); setSaveSearchName(''); const d=await apiFetch('/searches/saved'); if(d?.items)setSavedSearches(d.items) }
  const doLoadSavedSearch = (item:any) => { try{const p=typeof item.query_params==='string'?JSON.parse(item.query_params):item.query_params; setSq(p.regex||p.q||''); setRegexMode(!!p.regexMode); setSf({ext:p.ext||'',provider:p.provider||'',sort:p.sort||'relevance',page:1}); setShowSavedDropdown(false); doSearch(p.regex||p.q||'',{ext:p.ext||'',provider:p.provider||'',sort:p.sort||'relevance',page:1},!!p.regexMode)}catch{} }
  const doDeleteSavedSearch = async(id:number) => { await apiFetch(`/searches/saved/${id}`,{method:'DELETE'}); const d=await apiFetch('/searches/saved'); if(d?.items)setSavedSearches(d.items) }
  const doPreview = async(fileId:number) => { if(previewFile===fileId){setPreviewFile(null);setPreviewData(null);return} setPreviewFile(fileId); setPreviewLoading(true); const d=await apiFetch(`/files/${fileId}/preview`); setPreviewData(d); setPreviewLoading(false) }

  const doSearch = useCallback(async(q:string, f:any=sf, useRegex:boolean=regexMode) => { if(!q.trim())return; setSLoading(true); setView('search'); setSq(q); const p:any={...f}; if(useRegex){p.regex=q}else{p.q=q} Object.keys(p).forEach((k:string)=>!p[k]&&delete p[k]); const qs=new URLSearchParams(p).toString(); const d=await apiFetch(`/files?${qs}`); setSr(d||{items:[],total:0,page:1,per_page:50,query:q,response_time_ms:0}); setSLoading(false); setOnboarding(o=>({...o,firstSearch:true})) },[sf,regexMode])
  const loadBk = useCallback(async(f:any={}) => { const qs=new URLSearchParams(f).toString(); setBuckets(await apiFetch(`/buckets?${qs}`)||{items:[],total:0,page:1}); setView('buckets') },[])
  const loadBd = useCallback(async(id:number) => { setBd(await apiFetch(`/buckets/${id}`)||null); setView('bucket-detail') },[])
  const startScan = async() => {
    const d:any={keywords:scanForm.keywords.split(',').map((s:string)=>s.trim()).filter(Boolean),companies:scanForm.companies.split(',').map((s:string)=>s.trim()).filter(Boolean)}
    if(scanForm.providers.length)d.providers=scanForm.providers; if(!d.keywords.length&&!d.companies.length)return alert('Enter at least one keyword or company name')
    if(!sseConnected)connectSSE(); setScanProgress({phase:'starting',names_total:0,names_checked:0,buckets_found:0,buckets_open:0,files_indexed:0,errors:0}); setScanEvents([])
    const r=await apiFetch('/scans',{method:'POST',body:JSON.stringify(d)}); setScanStatus(r)
    if(r?.id){const pollId=setInterval(async()=>{const job=await apiFetch(`/scans/${r.id}`);if(!job)return;if(job.progress){try{setScanProgress(typeof job.progress==='string'?JSON.parse(job.progress):job.progress)}catch{}}
      setScanProgress((prev:any)=>({...prev,names_checked:job.names_checked||prev?.names_checked||0,buckets_found:job.buckets_found||prev?.buckets_found||0,buckets_open:job.buckets_open||prev?.buckets_open||0,files_indexed:job.files_indexed||prev?.files_indexed||0,phase:job.status==='completed'?'complete':job.status==='failed'?'failed':prev?.phase||'scanning'}))
      if(job.status==='completed'||job.status==='failed'||job.status==='cancelled'){clearInterval(pollId);apiFetch('/stats').then(d=>d&&setStats(d));loadScanHistory();if(job.status==='completed')setOnboarding(o=>({...o,firstScan:true}))}},2000)}
  }

  // ── AI helper functions ──
  const doNlSearch = async(q:string) => { if(!q.trim())return; setSLoading(true); setView('search'); setNlQuery(q); setSq(q); const d=await apiFetch('/ai/search',{method:'POST',body:JSON.stringify({query:q})}); if(d){setNlParsed(d.parsed_params);setSr(d)}else{setSr({items:[],total:0})}; setSLoading(false) }
  const doSuggestKw = async() => { const co=scanForm.companies.split(',').map(s=>s.trim()).filter(Boolean); if(!co.length)return; setSuggestLoading(true); const d=await apiFetch('/ai/suggest-keywords',{method:'POST',body:JSON.stringify({company:co[0]})}); if(d?.suggestions){setSuggestedKw(d.suggestions);const existing=scanForm.keywords?scanForm.keywords.split(',').map(s=>s.trim()).filter(Boolean):[]; const merged=[...new Set([...existing,...d.suggestions.slice(0,10)])]; setScanForm(f=>({...f,keywords:merged.join(', ')}))}; setSuggestLoading(false) }
  const doGenReport = async() => { setAiReportLoading(true); const d=await apiFetch('/ai/report',{method:'POST'}); if(d)setAiReport(d); setAiReportLoading(false) }
  const doClassifyBucket = async(bid:number) => { setClassifyLoading(true); await apiFetch(`/ai/classify/${bid}`,{method:'POST'}); await apiFetch(`/ai/risk/${bid}`,{method:'POST'}); const b=await apiFetch(`/buckets/${bid}`); if(b)setBd(b); const cs=await apiFetch(`/ai/classifications?bucket_id=${bid}`); if(cs)setAiClassSummary(cs.summary); setClassifyLoading(false) }
  const doPrioritizeAlerts = async() => { await apiFetch('/ai/prioritize-alerts',{method:'POST'}); loadMonitor() }
  const doSwitchProvider = async(name:string) => { setProviderSwitching(true); const r=await apiFetch('/ai/provider',{method:'POST',body:JSON.stringify({provider:name})}); if(r?.active_provider){setAiProvider(r.active_provider); const s=await apiFetch('/ai/status'); if(s){setAiAvail(s.available||false);setAiProviders(s.providers||[])}} setProviderSwitching(false) }
  // Sprint 3 handlers
  const resolveAlert = async(id:number) => { await apiFetch(`/monitor/alerts/${id}/resolve`,{method:'POST'}); loadMonitor() }
  const markAllAlertsRead = async() => { await apiFetch('/monitor/alerts/read-all',{method:'POST'}); loadMonitor() }
  const loadScanHistory = async() => { setScanHistoryLoading(true); const d=await apiFetch('/scans'); if(d?.items)setScanHistory(d.items); setScanHistoryLoading(false) }
  const cancelScan = async(id:number) => { await apiFetch(`/scans/${id}/cancel`,{method:'POST'}); loadScanHistory() }
  const rotateApiKey = async() => { if(!confirm('Rotate API key? The current key will stop working immediately.'))return; const r=await apiFetch('/auth/rotate-key',{method:'POST'}); if(r?.api_key){setUser((u:any)=>({...u,api_key:r.api_key}));setShowApiKey(true);setSettingsMsg('API key rotated successfully')} }
  const updateSettings = async() => { if(settingsForm.password&&settingsForm.password!==settingsForm.confirmPassword){setSettingsMsg('Passwords do not match');return} const body:any={}; if(settingsForm.username.trim())body.username=settingsForm.username.trim(); if(settingsForm.password)body.password=settingsForm.password; if(!Object.keys(body).length){setSettingsMsg('No changes to save');return} const r=await apiFetch('/auth/settings',{method:'PUT',body:JSON.stringify(body)}); if(r?.id){setUser(r);setSettingsMsg('Settings updated');setSettingsForm({username:'',password:'',confirmPassword:''})}else{setSettingsMsg(r?.error||'Update failed')} }
  const loadActivity = async(page:number=1) => { setActivityPage(page); const d=await apiFetch(`/activity?page=${page}&per_page=50`); if(d)setActivity(d) }

  // ═══════════════════════════════════════════════════════════════
  // ALL VIEWS INLINED — no component functions inside App()
  // This prevents React from remounting inputs on every state change
  // ═══════════════════════════════════════════════════════════════
  return (
    <div style={{minHeight:'100vh',background:'var(--bg-primary)',color:'var(--text-primary)',fontFamily:'var(--font-mono)'}}>
      {/* ─── WELCOME MODAL ─── */}
      {showWelcome && user && <div style={{position:'fixed',inset:0,zIndex:200,background:'rgba(0,0,0,0.7)',backdropFilter:'blur(8px)',display:'flex',alignItems:'center',justifyContent:'center'}} onClick={()=>setShowWelcome(false)}>
        <div onClick={e=>e.stopPropagation()} style={{width:520,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:16,padding:40,textAlign:'center'}} className="fade-in">
          <div style={{width:56,height:56,borderRadius:14,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:28,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900,marginBottom:16}}>☁</div>
          <h2 style={{fontSize:24,fontWeight:700,fontFamily:'var(--font-display)',margin:'0 0 8px'}}>Welcome, <span style={{color:'var(--accent)'}}>{user.username}</span>!</h2>
          <p style={{fontSize:13,color:'var(--text-tertiary)',margin:'0 0 28px'}}>Your CloudScan account is ready. Here's what you can do:</p>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:28}}>
            {[['⟳','Scan','Discover exposed buckets across cloud providers'],['⌕','Search','Find sensitive files with full-text & regex search'],['◉','Monitor','Set up watchlists for continuous monitoring'],['✦','AI','Get AI-powered security insights']].map(([ic,t,d]:any)=>
              <div key={t} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:10,padding:16,textAlign:'left'}}>
                <div style={{fontSize:20,marginBottom:6}}>{ic}</div>
                <div style={{fontSize:13,fontWeight:700,color:'var(--text-primary)',marginBottom:4}}>{t}</div>
                <div style={{fontSize:11,color:'var(--text-muted)',lineHeight:1.4}}>{d}</div></div>)}</div>
          {user.api_key && <div style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:10,padding:16,marginBottom:24,textAlign:'left'}}>
            <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:6,textTransform:'uppercase' as const,letterSpacing:'1px'}}>YOUR API KEY</div>
            <div style={{display:'flex',alignItems:'center',gap:8}}>
              <code style={{flex:1,fontSize:11,color:'var(--accent)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const,fontFamily:'var(--font-mono)'}}>{user.api_key}</code>
              <button onClick={()=>{navigator.clipboard.writeText(user.api_key);setCopiedKey(true);setTimeout(()=>setCopiedKey(false),2000)}} style={{background:copiedKey?'var(--accent-bg)':'var(--bg-secondary)',border:`1px solid ${copiedKey?'rgba(0,232,123,0.3)':'var(--border-subtle)'}`,color:copiedKey?'var(--accent)':'var(--text-secondary)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>{copiedKey?'Copied!':'Copy'}</button></div></div>}
          <button onClick={()=>setShowWelcome(false)} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:10,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',fontFamily:'var(--font-mono)'}}>Get Started</button>
        </div></div>}

      {/* ─── NAV ─── */}
      <nav style={{position:'fixed',top:0,left:0,right:0,zIndex:100,background:'var(--bg-secondary)',borderBottom:'1px solid var(--border-default)',backdropFilter:'blur(20px)',padding:'0 24px',height:56,display:'flex',alignItems:'center',gap:24}}>
        <div onClick={()=>setView('home')} style={{cursor:'pointer',display:'flex',alignItems:'center',gap:10}}>
          <div style={{width:28,height:28,borderRadius:6,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900}}>☁</div>
          <span style={{fontFamily:'var(--font-display)',fontWeight:700,fontSize:17,color:'var(--text-primary)',letterSpacing:'-0.5px'}}>Cloud<span style={{color:'var(--accent)'}}>Scan</span></span></div>
        <div style={{display:'flex',gap:4}}>
          {([['search','Files','⌕'],['buckets','Buckets','◫'],['scan','Scanner','⟳'],['monitor','Monitor','◉'],['ai-insights','AI','✦'],['activity','Activity','⏲'],['api-docs','API','{ }']]).map(([id,l,ic])=>(
            <button key={id} onClick={()=>{if(id==='buckets')loadBk();else if(id==='search'){setView('search');setTimeout(()=>ref.current?.focus(),100)}else if(id==='monitor')loadMonitor();else if(id==='ai-insights'){setView('ai-insights');apiFetch('/ai/classifications').then(d=>{if(d?.summary)setAiClassSummary(d.summary)})}else if(id==='scan'){setView('scan');loadScanHistory()}else if(id==='activity'){setView('activity');loadActivity()}else setView(id as string)}}
              style={{background:view===id?'var(--bg-tertiary)':'transparent',border:view===id?'1px solid var(--border-default)':'1px solid transparent',color:view===id?'var(--accent)':'var(--text-secondary)',padding:'6px 14px',borderRadius:8,cursor:'pointer',fontSize:13,fontFamily:'var(--font-mono)',transition:'all 0.15s'}}>
              <span style={{marginRight:5,fontSize:11}}>{ic}</span>{l}
              {id==='monitor'&&monDash?.unread_alerts?<span style={{background:'var(--danger)',color:'#fff',fontSize:9,padding:'1px 5px',borderRadius:8,marginLeft:5}}>{monDash.unread_alerts}</span>:null}
            </button>))}</div>
        <div style={{flex:1}}/>
        <button onClick={()=>setTheme(theme==='dark'?'light':'dark')} style={{background:'none',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'4px 8px',cursor:'pointer',fontSize:14,color:'var(--text-secondary)',lineHeight:1}} title={theme==='dark'?'Switch to light mode':'Switch to dark mode'}>{theme==='dark'?'☀':'☾'}</button>
        {sseConnected && <div style={{display:'flex',alignItems:'center',gap:5,fontSize:10,color:'var(--accent)'}}><div style={{width:6,height:6,borderRadius:'50%',background:'var(--accent)',animation:'pulse 2s infinite'}}/>LIVE</div>}
        {stats && <div style={{display:'flex',gap:20,fontSize:11,color:'var(--text-tertiary)'}}><span>◫ {fnum(stats.total_buckets)}</span><span>⬡ {fnum(stats.total_files)}</span><span>⬢ {fmt(stats.total_size_bytes)}</span></div>}
        {user ? <div style={{display:'flex',alignItems:'center',gap:10}}>
          <span style={{fontSize:11,color:'var(--text-secondary)'}}>{user.username}</span>
          <span style={{fontSize:9,background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'1px 6px',borderRadius:3,textTransform:'uppercase' as const}}>{user.tier}</span>
          <button onClick={()=>{setView('settings');apiFetch('/auth/me').then(d=>{if(d?.id)setUser(d)})}} style={{background:'none',border:'1px solid var(--border-subtle)',color:'var(--text-secondary)',padding:'4px 8px',borderRadius:6,cursor:'pointer',fontSize:13}} title="Settings">⚙</button>
          <button onClick={doLogout} style={{background:'none',border:'1px solid var(--border-subtle)',color:'var(--text-secondary)',padding:'4px 10px',borderRadius:8,cursor:'pointer',fontSize:11}}>Logout</button>
        </div> : <button onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('');setView('auth')}} style={{background:'var(--accent)',border:'none',color:'#000',padding:'6px 16px',borderRadius:8,cursor:'pointer',fontSize:12,fontWeight:600}}>Sign In</button>}
      </nav>

      {/* ─── AUTH ─── */}
      {view==='auth' && <div style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center'}}>
        <div style={{width:420,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:40}} className="fade-in">
          <div style={{textAlign:'center',marginBottom:32}}>
            <div style={{width:48,height:48,borderRadius:12,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:24,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900,marginBottom:12}}>☁</div>
            <h2 style={{fontSize:24,fontWeight:700,fontFamily:'var(--font-display)',margin:'0 0 4px'}}>Cloud<span style={{color:'var(--accent)'}}>Scan</span></h2>
            <p style={{fontSize:12,color:'var(--text-muted)',margin:0}}>
              {authMode==='login'?'Sign in to your account':authMode==='register'?'Create a new account':authMode==='forgot'?'Reset your password':'Set a new password'}
            </p></div>

          {/* Tab switcher — only for login/register */}
          {(authMode==='login'||authMode==='register') && <div style={{display:'flex',gap:4,marginBottom:24,background:'var(--bg-primary)',borderRadius:8,padding:4}}>
            {(['login','register'] as const).map(m=><button key={m} onClick={()=>{setAuthMode(m);setAuthError('');setAuthSuccess('')}} style={{flex:1,background:authMode===m?'var(--bg-tertiary)':'transparent',border:authMode===m?'1px solid var(--border-default)':'1px solid transparent',color:authMode===m?'var(--accent)':'var(--text-muted)',padding:'8px 0',borderRadius:4,cursor:'pointer',fontSize:12,fontWeight:600,textTransform:'capitalize' as const}}>{m}</button>)}</div>}

          {/* Back link for forgot/reset */}
          {(authMode==='forgot'||authMode==='reset') && <button onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('');setResetToken('')}} style={{background:'none',border:'none',color:'var(--text-tertiary)',cursor:'pointer',fontSize:12,padding:0,marginBottom:16}}>← Back to sign in</button>}

          {authError && <div style={{background:'#f0484815',border:'1px solid #f04848',borderRadius:8,padding:'8px 12px',marginBottom:16,fontSize:12,color:'#f04848'}}>{authError}</div>}
          {authSuccess && <div style={{background:'#00e87b10',border:'1px solid rgba(0,232,123,0.3)',borderRadius:8,padding:'8px 12px',marginBottom:16,fontSize:12,color:'var(--accent)'}}>{authSuccess}</div>}

          {/* Register: username */}
          {authMode==='register' && <div style={{marginBottom:16}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>USERNAME</label><input value={authForm.username} onChange={e=>setAuthForm({...authForm,username:e.target.value})} placeholder="your_username" style={IS}/></div>}

          {/* Login/Register/Forgot: email */}
          {(authMode==='login'||authMode==='register'||authMode==='forgot') && <div style={{marginBottom:16}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>EMAIL</label><input type="email" value={authForm.email} onChange={e=>setAuthForm({...authForm,email:e.target.value})} placeholder="you@company.com" onKeyDown={e=>e.key==='Enter'&&authMode==='forgot'&&doForgotPassword()} style={IS}/></div>}

          {/* Login/Register: password */}
          {(authMode==='login'||authMode==='register') && <div style={{marginBottom:authMode==='login'?12:24}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>PASSWORD</label><input type="password" value={authForm.password} onChange={e=>setAuthForm({...authForm,password:e.target.value})} placeholder="••••••••" onKeyDown={e=>e.key==='Enter'&&(authMode==='login'?doLogin():doRegister())} style={IS}/></div>}

          {/* Forgot password link */}
          {authMode==='login' && <div style={{textAlign:'right',marginBottom:20}}><span onClick={()=>{setAuthMode('forgot');setAuthError('');setAuthSuccess('')}} style={{fontSize:11,color:'var(--accent)',cursor:'pointer'}}>Forgot password?</span></div>}

          {/* Reset: new password */}
          {authMode==='reset' && <>
            <div style={{marginBottom:12}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>RESET TOKEN</label>
              <input value={resetToken} onChange={e=>setResetToken(e.target.value)} placeholder="Paste your reset token" style={{...IS,fontSize:11,color:'var(--text-secondary)'}}/></div>
            <div style={{marginBottom:24}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>NEW PASSWORD</label>
              <input type="password" value={authForm.password} onChange={e=>setAuthForm({...authForm,password:e.target.value})} placeholder="Minimum 8 characters" onKeyDown={e=>e.key==='Enter'&&doResetPassword()} style={IS}/></div>
          </>}

          {/* Action buttons */}
          {authMode==='login' && <button onClick={doLogin} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Signing in...':'Sign In'}</button>}
          {authMode==='register' && <button onClick={doRegister} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Creating...':'Create Account'}</button>}
          {authMode==='forgot' && <button onClick={doForgotPassword} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Sending...':'Send Reset Link'}</button>}
          {authMode==='reset' && <button onClick={doResetPassword} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Resetting...':'Reset Password'}</button>}

          {/* Footer links */}
          {authMode==='login' && <p style={{textAlign:'center',marginTop:16,fontSize:11,color:'var(--text-muted)'}}>No account? <span onClick={()=>{setAuthMode('register');setAuthError('');setAuthSuccess('')}} style={{color:'var(--accent)',cursor:'pointer'}}>Register</span></p>}
          {authMode==='register' && <p style={{textAlign:'center',marginTop:16,fontSize:11,color:'var(--text-muted)'}}>Already have an account? <span onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('')}} style={{color:'var(--accent)',cursor:'pointer'}}>Sign in</span></p>}
          {authMode==='forgot' && <p style={{textAlign:'center',marginTop:16,fontSize:11,color:'var(--text-muted)'}}>Already have a token? <span onClick={()=>{setAuthMode('reset');setAuthError('');setAuthSuccess('')}} style={{color:'var(--accent)',cursor:'pointer'}}>Reset password</span></p>}
        </div></div>}

      {/* ─── HOME ─── */}
      {view==='home' && <div style={{minHeight:'100vh',display:'flex',flexDirection:'column',alignItems:'center',background:'radial-gradient(ellipse 80% 50% at 50% -20%,#00e87b06 0%,transparent 60%),var(--bg-primary)',position:'relative',overflow:'hidden'}}>
        <div style={{position:'absolute',inset:0,opacity:0.025,backgroundImage:'linear-gradient(var(--accent) 1px,transparent 1px),linear-gradient(90deg,var(--accent) 1px,transparent 1px)',backgroundSize:'60px 60px'}}/>
        <div style={{position:'relative',textAlign:'center',maxWidth:800,padding:'80px 24px 40px'}}>
          {stats?.providers && <div style={{display:'flex',justifyContent:'center',gap:32,marginBottom:48}} className="fade-in">{stats.providers.map((p:any)=><div key={p.name} style={{textAlign:'center'}}><div style={{fontSize:24,fontWeight:800,fontFamily:'var(--font-display)',color:PC[p.name]?.bg||'#fff'}}>{fnum(p.bucket_count)}</div><div style={{fontSize:10,color:'var(--text-muted)',marginTop:2}}>{PL[p.name]||p.name}</div></div>)}</div>}
          <h1 style={{fontSize:52,fontWeight:800,lineHeight:1.05,margin:'0 0 16px',fontFamily:'var(--font-display)',background:'linear-gradient(135deg,var(--text-primary) 0%,var(--text-secondary) 100%)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}} className="fade-in">Search Open<br/>Cloud Storage</h1>
          <p style={{fontSize:14,color:'var(--text-tertiary)',lineHeight:1.6,margin:'0 auto 40px',maxWidth:520}}>Discover exposed buckets & files across <span style={{color:'var(--aws)'}}>AWS</span>, <span style={{color:'var(--azure)'}}>Azure</span>, <span style={{color:'var(--gcp)'}}>GCP</span>, <span style={{color:'var(--digitalocean)'}}>DigitalOcean</span> & <span style={{color:'var(--alibaba)'}}>Alibaba</span></p>
          <div style={{position:'relative',maxWidth:620,margin:'0 auto 24px'}} className="slide-up">
            <div style={{display:'flex',background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,overflow:'hidden',boxShadow:'0 0 40px var(--accent-glow),0 4px 24px rgba(0,0,0,0.4)'}}>
              <span style={{display:'flex',alignItems:'center',padding:'0 16px',color:'var(--text-muted)',fontSize:18}}>⌕</span>
              <input value={heroQ} onChange={e=>setHeroQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSearch(heroQ)} placeholder="Search files... (.env, backup.sql, credentials)" style={{flex:1,background:'none',border:'none',color:'var(--text-primary)',fontSize:15,padding:'16px 0',fontFamily:'var(--font-mono)'}}/>
              <button onClick={()=>doSearch(heroQ)} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',padding:'0 28px',cursor:'pointer',color:'#000',fontWeight:700,fontSize:13,fontFamily:'var(--font-mono)'}}>SEARCH</button></div></div>
          <div style={{display:'flex',gap:8,justifyContent:'center',flexWrap:'wrap'}}>{['.env','backup.sql','credentials.json','id_rsa','terraform.tfstate','.key','*.csv'].map(q=><button key={q} onClick={()=>{setHeroQ(q);doSearch(q)}} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'5px 12px',color:'var(--text-tertiary)',fontSize:12,cursor:'pointer',fontFamily:'var(--font-mono)'}}>{q}</button>)}</div>
          {user && <div style={{marginTop:20,textAlign:'center'}}>
            <button onClick={()=>{setScanForm({keywords:'backup, staging, dev, test, config',companies:'example',providers:[]});setView('scan');loadScanHistory()}} style={{background:'var(--bg-secondary)',border:'1px solid var(--accent)',borderRadius:10,padding:'12px 28px',cursor:'pointer',color:'var(--accent)',fontSize:13,fontWeight:700,fontFamily:'var(--font-mono)',transition:'all 0.15s'}}>⟳ Try a Demo Scan</button>
            <p style={{fontSize:11,color:'var(--text-muted)',marginTop:8}}>Pre-filled with common keywords to discover exposed buckets</p></div>}
          {stats?.top_extensions && <div style={{marginTop:64,display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(85px,1fr))',gap:8,maxWidth:550,margin:'64px auto 0'}}>{stats.top_extensions.slice(0,12).map((e:any)=><div key={e.extension} onClick={()=>doSearch(`*.${e.extension}`)} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:8,cursor:'pointer',textAlign:'center'}}>
            <span style={{fontSize:16}}>{EI[e.extension]||'📄'}</span><div style={{fontSize:11,color:'var(--accent)',fontWeight:600}}>.{e.extension}</div><div style={{fontSize:10,color:'var(--text-muted)'}}>{fnum(e.count)}</div></div>)}</div>}

          {/* Onboarding Checklist */}
          {user && !onboarding.dismissed && <div style={{marginTop:40,maxWidth:600,margin:'40px auto 0',background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,textAlign:'left'}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16}}>
              <div><div style={{fontSize:14,fontWeight:700,fontFamily:'var(--font-display)',color:'var(--text-primary)'}}>Getting Started</div>
                <div style={{fontSize:11,color:'var(--text-muted)',marginTop:2}}>{[true,onboarding.firstScan,onboarding.firstSearch,onboarding.firstMonitor].filter(Boolean).length}/4 complete</div></div>
              <button onClick={()=>setOnboarding(o=>({...o,dismissed:true}))} style={{background:'none',border:'none',color:'var(--text-muted)',cursor:'pointer',fontSize:14,padding:4}}>✕</button></div>
            <div style={{background:'var(--bg-primary)',borderRadius:4,height:4,marginBottom:16,overflow:'hidden'}}><div style={{height:'100%',background:'linear-gradient(90deg,var(--accent),#00c568)',borderRadius:4,width:`${[true,onboarding.firstScan,onboarding.firstSearch,onboarding.firstMonitor].filter(Boolean).length*25}%`,transition:'width 0.5s'}}/></div>
            {([
              [true,'Registered','Create your CloudScan account',null],
              [onboarding.firstScan,'First Scan','Run a discovery scan to find exposed buckets',()=>{setScanForm({keywords:'backup, staging, dev, test',companies:'example',providers:[]});setView('scan');loadScanHistory()}],
              [onboarding.firstSearch,'First Search','Search for exposed files in the database',()=>{setView('search');setTimeout(()=>ref.current?.focus(),100)}],
              [onboarding.firstMonitor,'Set Up Monitoring','Create a watchlist for continuous monitoring',()=>loadMonitor()]
            ] as [boolean,string,string,(()=>void)|null][]).map(([done,title,desc,action])=>
              <div key={title} style={{display:'flex',alignItems:'center',gap:12,padding:'10px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                <div style={{width:22,height:22,borderRadius:'50%',border:`2px solid ${done?'var(--accent)':'var(--border-default)'}`,background:done?'var(--accent)':'transparent',display:'flex',alignItems:'center',justifyContent:'center',fontSize:11,color:done?'#000':'transparent',flexShrink:0}}>{done?'✓':''}</div>
                <div style={{flex:1}}><div style={{fontSize:13,fontWeight:600,color:done?'var(--text-tertiary)':'var(--text-primary)',textDecoration:done?'line-through':'none'}}>{title}</div>
                  <div style={{fontSize:11,color:'var(--text-muted)'}}>{desc}</div></div>
                {!done&&action&&<button onClick={action} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>Start</button>}
              </div>)}</div>}

          {/* Dashboard Analytics */}
          {(dashBreakdown || dashTimeline) && <div style={{marginTop:64,maxWidth:900,margin:'64px auto 0'}}>
            <h3 style={{fontSize:16,fontWeight:700,fontFamily:'var(--font-display)',textAlign:'center',marginBottom:24,color:'var(--text-secondary)'}}>Analytics</h3>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:24}}>

              {/* Risk Distribution */}
              {dashBreakdown?.risk_distribution && <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20}}>
                <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',marginBottom:12}}>Risk Levels</div>
                {dashBreakdown.risk_distribution.length>0 ? dashBreakdown.risk_distribution.map((r:any)=>{const mx=Math.max(...dashBreakdown.risk_distribution.map((x:any)=>x.count));const pct=mx?(r.count/mx)*100:0;const rc:any={critical:'#f04848',high:'#ff6b35',medium:'#f5a623',low:'#4a9eff',info:'#4a5f73'};return <div key={r.risk_level} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <span style={{width:70,fontSize:10,color:rc[r.risk_level]||'var(--text-secondary)',fontWeight:600,textTransform:'uppercase' as const}}>{r.risk_level}</span>
                  <div style={{flex:1,background:'var(--bg-primary)',borderRadius:4,height:16,overflow:'hidden'}}><div style={{width:`${pct}%`,height:'100%',background:rc[r.risk_level]||'var(--accent)',borderRadius:4,transition:'width 0.5s'}}/></div>
                  <span style={{width:40,fontSize:10,color:'var(--text-muted)',textAlign:'right'}}>{fnum(r.count)}</span></div>})
                : <div style={{fontSize:11,color:'var(--text-muted)',textAlign:'center',padding:20}}>No risk data yet</div>}
              </div>}
            </div>

            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
              {/* Status Distribution */}
              {dashBreakdown?.status_distribution && <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20}}>
                <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',marginBottom:12}}>Bucket Status</div>
                {dashBreakdown.status_distribution.map((s:any)=>{const sc:any={open:'var(--accent)',closed:'#f04848',partial:'var(--warning)'};return <div key={s.status} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <span style={{width:70,fontSize:10,color:sc[s.status]||'var(--text-secondary)',fontWeight:600,textTransform:'uppercase' as const}}>{s.status}</span>
                  <div style={{flex:1,background:'var(--bg-primary)',borderRadius:4,height:16,overflow:'hidden'}}><div style={{width:'100%',height:'100%',background:sc[s.status]||'var(--text-muted)',borderRadius:4,opacity:0.4}}/></div>
                  <span style={{width:40,fontSize:10,color:'var(--text-muted)',textAlign:'right'}}>{fnum(s.count)}</span></div>})}
              </div>}

              {/* Discovery Timeline */}
              {dashTimeline?.files_timeline && <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20}}>
                <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',marginBottom:12}}>Files Discovered (30d)</div>
                {dashTimeline.files_timeline.length>0 ? <div style={{display:'flex',alignItems:'flex-end',gap:2,height:80}}>
                  {dashTimeline.files_timeline.map((d:any,i:number)=>{const mx=Math.max(...dashTimeline.files_timeline.map((x:any)=>x.count));const h=mx?(d.count/mx)*100:0;return <div key={i} title={`${d.day}: ${d.count} files`} style={{flex:1,background:'var(--accent)',borderRadius:'2px 2px 0 0',height:`${Math.max(h,2)}%`,opacity:0.7,transition:'height 0.3s',minWidth:2}}/>})}
                </div> : <div style={{fontSize:11,color:'var(--text-muted)',textAlign:'center',padding:20}}>No timeline data yet</div>}
              </div>}
            </div>

            {/* Classification Breakdown */}
            {dashBreakdown?.classification_distribution && dashBreakdown.classification_distribution.length>0 && <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20,marginTop:16}}>
              <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',marginBottom:12}}>File Classifications</div>
              <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(150px,1fr))',gap:8}}>
                {dashBreakdown.classification_distribution.map((c:any)=><div key={c.ai_classification} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:12,display:'flex',alignItems:'center',gap:8}}>
                  <ClassBadge c={c.ai_classification}/><span style={{fontSize:16,fontWeight:700,fontFamily:'var(--font-display)',color:'var(--text-secondary)'}}>{fnum(c.count)}</span></div>)}
              </div>
            </div>}
          </div>}
        </div></div>}

      {/* ─── SEARCH ─── */}
      {view==='search' && <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <LiveScanPanel progress={scanProgress} events={scanEvents}/>
        <div style={{display:'flex',gap:8,marginBottom:16,background:'var(--bg-secondary)',border:`1px solid ${nlMode?'var(--ai-accent-dim)':'var(--border-default)'}`,borderRadius:12,padding:'4px 4px 4px 16px',alignItems:'center'}}>
          <span style={{color:nlMode?'var(--ai-accent)':regexMode?'var(--warning)':'var(--text-muted)',fontSize:16}}>{nlMode?'✦':regexMode?'.*':'⌕'}</span>
          <input ref={ref} value={sq} onChange={e=>setSq(e.target.value)} onKeyDown={e=>e.key==='Enter'&&(nlMode?doNlSearch(sq):doSearch(sq))} placeholder={nlMode?'Ask in plain English... e.g. "find database backups from tech companies"':regexMode?'Regex pattern on filepath... e.g. .*\\.env$':'Search files...'} style={{flex:1,background:'none',border:'none',color:'var(--text-primary)',fontSize:14,padding:'12px 0',fontFamily:'var(--font-mono)'}}/>
          {!nlMode && <button onClick={()=>setRegexMode(!regexMode)} style={{background:regexMode?'var(--warning)20':'var(--bg-primary)',border:`1px solid ${regexMode?'var(--warning)':'var(--border-subtle)'}`,color:regexMode?'var(--warning)':'var(--text-muted)',padding:'4px 10px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:700,whiteSpace:'nowrap' as const,fontFamily:'var(--font-mono)'}}>.*</button>}
          {aiAvail && <button onClick={()=>{setNlMode(!nlMode);if(!nlMode)setRegexMode(false)}} style={{background:nlMode?'var(--ai-accent)20':'var(--bg-primary)',border:`1px solid ${nlMode?'var(--ai-accent)':'var(--border-subtle)'}`,color:nlMode?'var(--ai-accent)':'var(--text-muted)',padding:'4px 10px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:700,whiteSpace:'nowrap' as const}}>AI</button>}
          <button onClick={()=>nlMode?doNlSearch(sq):doSearch(sq)} style={{background:nlMode?'linear-gradient(135deg,#a855f7,#7c3aed)':regexMode?'var(--warning)':'var(--accent)',border:'none',padding:'8px 20px',borderRadius:8,cursor:'pointer',color:nlMode?'#fff':'#000',fontWeight:700,fontSize:12}}>SEARCH</button></div>
        {nlMode && nlParsed && <div style={{marginBottom:12,padding:'8px 14px',background:'var(--ai-accent-glow)',border:'1px solid #a855f730',borderRadius:8,fontSize:11,color:'var(--text-secondary)'}}>AI parsed: {Object.entries(nlParsed).map(([k,v])=><span key={k} style={{marginRight:10}}><span style={{color:'var(--ai-accent)'}}>{k}</span>=<span style={{color:'var(--text-primary)'}}>{String(v)}</span></span>)}</div>}
        <div style={{display:'flex',gap:10,marginBottom:20,flexWrap:'wrap',alignItems:'center'}}>
          {!nlMode && <select value={sf.provider} onChange={e=>{const f={...sf,provider:e.target.value,page:1};setSf(f);if(sq)doSearch(sq,f)}} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:8,color:'var(--text-secondary)',padding:'6px 12px',fontSize:12}}><option value="">All Providers</option>{Object.entries(PL).map(([k,v])=><option key={k} value={k}>{v as string}</option>)}</select>}
          {!nlMode && <select value={sf.sort} onChange={e=>{const f={...sf,sort:e.target.value};setSf(f);if(sq)doSearch(sq,f)}} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:8,color:'var(--text-secondary)',padding:'6px 12px',fontSize:12}}><option value="relevance">Relevance</option><option value="size_desc">Largest</option><option value="size_asc">Smallest</option><option value="newest">Newest</option><option value="filename">Filename</option></select>}
          {sr && <span style={{fontSize:11,color:'var(--text-muted)',marginLeft:'auto'}}>{fnum(sr.total)} results · {sr.response_time_ms}ms</span>}
          {sr && sr.total>0 && <>{['CSV','JSON'].map(fmt=><button key={fmt} onClick={()=>{const p:any={format:fmt.toLowerCase()};if(regexMode){p.regex=sq}else{p.q=sq}if(sf.ext)p.ext=sf.ext;if(sf.provider)p.provider=sf.provider;window.open(`${API}/files/export?${new URLSearchParams(p).toString()}`,'_blank')}} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'4px 10px',color:'var(--text-tertiary)',fontSize:10,cursor:'pointer',fontWeight:600}}>{fmt}</button>)}</>}
          {user && sr && sr.total>0 && <div style={{position:'relative'}}><button onClick={()=>setShowSavedDropdown(!showSavedDropdown)} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'4px 10px',color:'var(--text-tertiary)',fontSize:10,cursor:'pointer',fontWeight:600}}>💾 Save</button>
            {showSavedDropdown && <div style={{position:'absolute',right:0,top:'100%',marginTop:4,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:8,padding:12,zIndex:100,minWidth:260,boxShadow:'0 8px 32px rgba(0,0,0,0.4)'}}>
              <div style={{display:'flex',gap:6,marginBottom:8}}><input value={saveSearchName} onChange={e=>setSaveSearchName(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSaveSearch()} placeholder="Search name..." style={{...IS,fontSize:11,padding:'6px 10px',flex:1}}/><button onClick={doSaveSearch} style={{background:'var(--accent)',border:'none',borderRadius:6,padding:'6px 12px',color:'#000',fontSize:10,fontWeight:700,cursor:'pointer'}}>Save</button></div>
              {savedSearches.length>0 && <div style={{borderTop:'1px solid var(--border-subtle)',paddingTop:8,maxHeight:200,overflow:'auto'}}>{savedSearches.map((s:any)=><div key={s.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'4px 0',gap:8}}>
                <span onClick={()=>doLoadSavedSearch(s)} style={{fontSize:11,color:'var(--accent-dim)',cursor:'pointer',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{s.name}</span>
                <button onClick={()=>doDeleteSavedSearch(s.id)} style={{background:'none',border:'none',color:'var(--text-muted)',cursor:'pointer',fontSize:10,padding:0}}>✕</button></div>)}</div>}
            </div>}</div>}</div>
        {sLoading ? <Spin/> : sr?.items?.length ? <div style={{display:'flex',flexDirection:'column',gap:1}}>
          <div style={{display:'grid',gridTemplateColumns:'30px 1fr 95px 80px 85px 75px 110px',gap:12,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}><span/><span>File</span><span>Provider</span><span>Class</span><span>Size</span><span>Age</span><span>Bucket</span></div>
          {sr.items.map((f:any,i:number)=><div key={f.id||i}>
            <div onClick={()=>doPreview(f.id)} style={{display:'grid',gridTemplateColumns:'30px 1fr 95px 80px 85px 75px 110px',gap:12,padding:'10px 16px',alignItems:'center',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4,cursor:'pointer'}}>
            <span style={{fontSize:17,textAlign:'center'}}>{EI[f.extension]||'📄'}</span>
            <div style={{minWidth:0}}><div style={{fontSize:13,whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}><a href={f.url} target="_blank" rel="noopener noreferrer" style={{color:'var(--accent-dim)'}} onClick={e=>e.stopPropagation()}>{f.filename}</a></div><div style={{fontSize:11,color:'var(--text-muted)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{f.filepath}</div></div>
            <Badge provider={f.provider_name}/>{f.ai_classification?<ClassBadge c={f.ai_classification}/>:<span style={{fontSize:10,color:'var(--text-muted)'}}>—</span>}<span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fmt(f.size_bytes)}</span><span style={{fontSize:11,color:'var(--text-muted)'}}>{ago(f.last_modified)}</span>
            <span style={{fontSize:11,color:'var(--accent-dim)',cursor:'pointer',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}} onClick={e=>{e.stopPropagation();loadBd(f.bucket_id)}}>{f.bucket_name}</span></div>
            {previewFile===f.id && <div style={{padding:'12px 16px 12px 58px',background:'var(--bg-primary)',borderBottom:'1px solid var(--border-subtle)'}}>
              {previewLoading ? <div style={{fontSize:11,color:'var(--text-muted)'}}>Loading preview...</div>
              : previewData?.preview_type==='text' ? <div><pre style={{background:'#0d1117',border:'1px solid var(--border-subtle)',borderRadius:6,padding:12,fontSize:11,color:'#c9d1d9',maxHeight:300,overflow:'auto',whiteSpace:'pre-wrap' as const,wordBreak:'break-all' as const,margin:0,fontFamily:'var(--font-mono)'}}>{previewData.content}</pre>{previewData.truncated&&<div style={{fontSize:10,color:'var(--text-muted)',marginTop:4}}>Truncated at 4KB — full file: {fmt(previewData.size_bytes)}</div>}</div>
              : previewData?.preview_type==='binary' ? <div style={{fontSize:11,color:'var(--text-muted)'}}>{previewData.summary}</div>
              : <div style={{fontSize:11,color:'var(--text-muted)'}}>{previewData?.error||'Preview unavailable'}</div>}
            </div>}
          </div>)}
        </div> : sr ? <div style={{textAlign:'center',padding:60,color:'var(--text-muted)'}}>No results for "{sr.query}"</div> : <div style={{textAlign:'center',padding:60,color:'var(--text-muted)'}}>Enter a query to search exposed files</div>}
        {sr && sr.total > (sr.per_page||50) && (()=>{ const tp=Math.ceil(sr.total/(sr.per_page||50)),cp=sr.page||1; const pages:number[]=[]; if(tp<=7){for(let i=1;i<=tp;i++)pages.push(i)}else{pages.push(1);if(cp>3)pages.push(-1);for(let i=Math.max(2,cp-1);i<=Math.min(tp-1,cp+1);i++)pages.push(i);if(cp<tp-2)pages.push(-1);pages.push(tp)} return <div style={{display:'flex',justifyContent:'center',alignItems:'center',gap:6,marginTop:16}}>
          <button onClick={()=>{const f={...sf,page:cp-1};setSf(f);doSearch(sq,f)}} disabled={cp===1} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'5px 12px',color:cp===1?'var(--text-muted)':'var(--text-secondary)',fontSize:11,cursor:cp===1?'default':'pointer'}}>Prev</button>
          {pages.map((p,i)=>p===-1?<span key={'e'+i} style={{color:'var(--text-muted)',fontSize:11}}>...</span>:<button key={p} onClick={()=>{const f={...sf,page:p};setSf(f);doSearch(sq,f)}} style={{background:p===cp?'var(--accent)':'var(--bg-secondary)',border:`1px solid ${p===cp?'var(--accent)':'var(--border-subtle)'}`,borderRadius:6,padding:'5px 10px',color:p===cp?'#000':'var(--text-secondary)',fontSize:11,fontWeight:p===cp?700:400,cursor:'pointer',minWidth:32}}>{p}</button>)}
          <button onClick={()=>{const f={...sf,page:cp+1};setSf(f);doSearch(sq,f)}} disabled={cp===tp} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'5px 12px',color:cp===tp?'var(--text-muted)':'var(--text-secondary)',fontSize:11,cursor:cp===tp?'default':'pointer'}}>Next</button>
          <span style={{fontSize:10,color:'var(--text-muted)',marginLeft:8}}>Page {cp} of {tp}</span></div> })()}
      </div>}

      {/* ─── BUCKETS ─── */}
      {view==='buckets' && <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20,flexWrap:'wrap',gap:12}}>
          <h2 style={{fontSize:20,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>Public Buckets <span style={{fontSize:13,color:'var(--text-muted)',marginLeft:12}}>{fnum(buckets?.total||0)} indexed</span></h2>
          <div style={{display:'flex',gap:6}}>{['all','aws','azure','gcp','digitalocean','alibaba'].map(p=><button key={p} onClick={()=>loadBk(p==='all'?{}:{provider:p})} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'5px 12px',color:'var(--text-tertiary)',fontSize:11,cursor:'pointer'}}>{p==='all'?'All':PL[p]}</button>)}</div></div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 95px 85px 75px 90px 85px 85px 75px',gap:12,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}><span>Bucket</span><span>Provider</span><span>Region</span><span>Status</span><span>Risk</span><span>Files</span><span>Size</span><span>Scanned</span></div>
        {buckets?.items?.map((b:any,i:number)=><div key={b.id} onClick={()=>loadBd(b.id)} style={{display:'grid',gridTemplateColumns:'1fr 95px 85px 75px 90px 85px 85px 75px',gap:12,padding:'12px 16px',alignItems:'center',cursor:'pointer',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4}}>
          <span style={{fontSize:14,color:'var(--accent-dim)',fontWeight:600}}>{b.name}</span><Badge provider={b.provider_name}/><span style={{fontSize:12,color:'var(--text-muted)'}}>{b.region||'—'}</span><SBadge s={b.status}/>{b.risk_score!=null?<RiskBadge score={b.risk_score} level={b.risk_level||'info'}/>:<span style={{fontSize:10,color:'var(--text-muted)'}}>—</span>}<span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fnum(b.file_count)}</span><span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fmt(b.total_size_bytes)}</span><span style={{fontSize:11,color:'var(--text-muted)'}}>{ago(b.last_scanned)}</span></div>)}
        {buckets && buckets.total > (buckets.per_page||50) && (()=>{ const tp=Math.ceil(buckets.total/(buckets.per_page||50)),cp=buckets.page||1; const pages:number[]=[]; if(tp<=7){for(let i=1;i<=tp;i++)pages.push(i)}else{pages.push(1);if(cp>3)pages.push(-1);for(let i=Math.max(2,cp-1);i<=Math.min(tp-1,cp+1);i++)pages.push(i);if(cp<tp-2)pages.push(-1);pages.push(tp)} return <div style={{display:'flex',justifyContent:'center',alignItems:'center',gap:6,marginTop:16}}>
          <button onClick={()=>loadBk({page:cp-1})} disabled={cp===1} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'5px 12px',color:cp===1?'var(--text-muted)':'var(--text-secondary)',fontSize:11,cursor:cp===1?'default':'pointer'}}>Prev</button>
          {pages.map((p,i)=>p===-1?<span key={'e'+i} style={{color:'var(--text-muted)',fontSize:11}}>...</span>:<button key={p} onClick={()=>loadBk({page:p})} style={{background:p===cp?'var(--accent)':'var(--bg-secondary)',border:`1px solid ${p===cp?'var(--accent)':'var(--border-subtle)'}`,borderRadius:6,padding:'5px 10px',color:p===cp?'#000':'var(--text-secondary)',fontSize:11,fontWeight:p===cp?700:400,cursor:'pointer',minWidth:32}}>{p}</button>)}
          <button onClick={()=>loadBk({page:cp+1})} disabled={cp===tp} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'5px 12px',color:cp===tp?'var(--text-muted)':'var(--text-secondary)',fontSize:11,cursor:cp===tp?'default':'pointer'}}>Next</button>
          <span style={{fontSize:10,color:'var(--text-muted)',marginLeft:8}}>Page {cp} of {tp}</span></div> })()}
      </div>}

      {/* ─── BUCKET DETAIL ─── */}
      {view==='bucket-detail' && (bd ? <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <button onClick={()=>setView('buckets')} style={{background:'none',border:'none',color:'var(--text-tertiary)',cursor:'pointer',fontSize:12,marginBottom:16,padding:0}}>← Back</button>
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:24}}>
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:16,flexWrap:'wrap'}}><h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>{bd.name}</h2><Badge provider={bd.provider_name} big/><SBadge s={bd.status}/>{bd.risk_score!=null&&<RiskBadge score={bd.risk_score} level={bd.risk_level||'info'}/>}
            {aiAvail&&<button onClick={()=>doClassifyBucket(bd.id)} disabled={classifyLoading} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'5px 14px',borderRadius:6,cursor:'pointer',color:'#fff',fontSize:11,fontWeight:600,opacity:classifyLoading?0.5:1}}>{classifyLoading?'Analyzing...':'✦ AI Analyze'}</button>}</div>
          {aiClassSummary && Object.keys(aiClassSummary).length>0 && <div style={{display:'flex',gap:8,marginBottom:16,flexWrap:'wrap'}}>{Object.entries(aiClassSummary).map(([cat,cnt]:any)=><div key={cat} style={{display:'flex',alignItems:'center',gap:4}}><ClassBadge c={cat}/><span style={{fontSize:11,color:'var(--text-muted)'}}>{cnt}</span></div>)}</div>}
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:16}}>{[['URL',bd.url],['Region',bd.region||'Global'],['Files',fnum(bd.file_count)],['Size',fmt(bd.total_size_bytes)],['First Seen',bd.first_seen?.split('T')[0]],['Last Scanned',ago(bd.last_scanned)]].map(([l,v]:any)=><div key={l}><div style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase' as const,marginBottom:4}}>{l}</div><div style={{fontSize:13,color:'var(--text-secondary)',wordBreak:'break-all' as const}}>{v||'—'}</div></div>)}</div></div>
        <h3 style={{fontSize:14,color:'var(--text-tertiary)',marginBottom:12}}>Contents ({fnum(bd.files?.total||0)} files)</h3>
        {bd.files?.items?.map((f:any,i:number)=><div key={f.id||i} style={{display:'grid',gridTemplateColumns:'28px 1fr 80px 85px 75px',gap:12,padding:'8px 12px',alignItems:'center',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4}}>
          <span style={{fontSize:16}}>{EI[f.extension]||'📄'}</span><a href={f.url} target="_blank" rel="noopener noreferrer" style={{fontSize:12,color:'var(--accent-dim)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{f.filepath}</a>{f.ai_classification?<ClassBadge c={f.ai_classification}/>:<span style={{fontSize:10,color:'var(--text-muted)'}}>—</span>}<span style={{fontSize:11,color:'var(--text-muted)'}}>{fmt(f.size_bytes)}</span><span style={{fontSize:10,color:'var(--text-muted)'}}>{ago(f.last_modified)}</span></div>)}
      </div> : <Spin/>)}

      {/* ─── SCANNER ─── */}
      {view==='scan' && <div style={{padding:'80px 24px 24px',maxWidth:800,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Bucket Discovery Scanner</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24}}>Real-time scanning across all major cloud providers.</p>
        <LiveScanPanel progress={scanProgress} events={scanEvents}/>
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:28}}>
          <div style={{marginBottom:20}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>KEYWORDS (comma-separated)</label>
            <input value={scanForm.keywords} onChange={e=>setScanForm({...scanForm,keywords:e.target.value})} placeholder="backup, database, config, secret" style={IS}/></div>
          <div style={{marginBottom:20}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>TARGET COMPANIES (comma-separated)</label>
            <div style={{display:'flex',gap:8}}><input value={scanForm.companies} onChange={e=>setScanForm({...scanForm,companies:e.target.value})} placeholder="acme-corp, globex, initech" style={{...IS,flex:1}}/>
            {aiAvail&&<button onClick={doSuggestKw} disabled={suggestLoading||!scanForm.companies.trim()} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'10px 16px',borderRadius:8,cursor:suggestLoading||!scanForm.companies.trim()?'not-allowed':'pointer',color:'#fff',fontSize:11,fontWeight:600,whiteSpace:'nowrap' as const,opacity:suggestLoading||!scanForm.companies.trim()?0.5:1}}>{suggestLoading?'...':'✦ Suggest'}</button>}</div>
            {suggestedKw.length>0&&<div style={{marginTop:8,display:'flex',gap:4,flexWrap:'wrap'}}>{suggestedKw.map((kw:string)=><span key={kw} style={{background:'#a855f710',border:'1px solid #a855f730',color:'#a855f7',padding:'2px 8px',borderRadius:4,fontSize:10}}>{kw}</span>)}</div>}</div>
          <div style={{marginBottom:24}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:8}}>PROVIDERS</label>
            <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>{Object.entries(PL).map(([k,l])=>{const a=scanForm.providers.includes(k);return <button key={k} onClick={()=>setScanForm({...scanForm,providers:a?scanForm.providers.filter(p=>p!==k):[...scanForm.providers,k]})} style={{background:a?PC[k].bg+'20':'var(--bg-primary)',border:`1px solid ${a?PC[k].bg:'var(--border-subtle)'}`,borderRadius:8,padding:'6px 14px',cursor:'pointer',color:a?PC[k].bg:'var(--text-muted)',fontSize:12,fontWeight:a?600:400}}>{l as string}</button>})}</div></div>
          <button onClick={startScan} disabled={scanProgress?.phase==='scanning'} style={{width:'100%',background:scanProgress?.phase==='scanning'?'var(--bg-tertiary)':'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:scanProgress?.phase==='scanning'?'var(--text-tertiary)':'#000',fontWeight:700,fontSize:14,cursor:scanProgress?.phase==='scanning'?'not-allowed':'pointer',fontFamily:'var(--font-mono)'}}>{scanProgress?.phase==='scanning'?'⟳ SCAN IN PROGRESS...':'⟳ START DISCOVERY SCAN'}</button>
        </div>
        {/* Scan History */}
        {scanHistory.length>0 && <div style={{marginTop:32}}>
          <h3 style={{fontSize:15,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:12}}>Scan History</h3>
          <div style={{display:'grid',gridTemplateColumns:'90px 1fr 80px 80px 80px 80px 70px',gap:8,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}><span>Status</span><span>Config</span><span>Checked</span><span>Buckets</span><span>Files</span><span>Time</span><span/></div>
          {scanHistory.map((j:any,i:number)=>{const sc:any={completed:'var(--accent)',failed:'var(--danger)',cancelled:'var(--text-muted)',running:'var(--info)',pending:'var(--warning)'}; const cfg=typeof j.config==='string'?JSON.parse(j.config||'{}'):j.config||{}; return <div key={j.id} style={{display:'grid',gridTemplateColumns:'90px 1fr 80px 80px 80px 80px 70px',gap:8,padding:'10px 16px',alignItems:'center',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4}}>
            <span style={{fontSize:10,fontWeight:600,color:sc[j.status]||'var(--text-muted)',textTransform:'uppercase' as const}}>{j.status}</span>
            <span style={{fontSize:11,color:'var(--text-secondary)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{(cfg.keywords||[]).join(', ')||(cfg.companies||[]).join(', ')||'—'}</span>
            <span style={{fontSize:11,color:'var(--text-secondary)'}}>{fnum(j.names_checked||0)}</span>
            <span style={{fontSize:11,color:'var(--accent)'}}>{j.buckets_found||0} ({j.buckets_open||0})</span>
            <span style={{fontSize:11,color:'var(--text-secondary)'}}>{fnum(j.files_indexed||0)}</span>
            <span style={{fontSize:10,color:'var(--text-muted)'}}>{ago(j.started_at||j.created_at)}</span>
            {(j.status==='running'||j.status==='pending')?<button onClick={()=>cancelScan(j.id)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--danger)',padding:'3px 8px',borderRadius:6,cursor:'pointer',fontSize:10}}>Cancel</button>:<span/>}
          </div>})}
        </div>}
        </div>}

      {/* ─── MONITOR ─── */}
      {view==='monitor' && <div style={{padding:'80px 24px 24px',maxWidth:1100,margin:'0 auto'}}>
        {!user ? <div style={{textAlign:'center',padding:80}}>
          <div style={{fontSize:48,marginBottom:16}}>🛡</div><h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Attack Surface Monitoring</h2>
          <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24,maxWidth:500,margin:'0 auto 24px'}}>Continuously monitor your organization's cloud storage exposure.</p>
          <button onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('');setView('auth')}} style={{background:'var(--accent)',border:'none',color:'#000',padding:'10px 28px',borderRadius:8,cursor:'pointer',fontSize:13,fontWeight:700}}>Sign In to Get Started</button>
        </div> : <>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:24}}><h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>🛡 Attack Surface Monitor</h2><span style={{fontSize:11,color:'var(--text-muted)'}}>Logged in as <span style={{color:'var(--accent)'}}>{user.username}</span></span></div>
          {monDash && <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:32}}>{[['Watchlists',monDash.watchlists,'◉','var(--accent)'],['Monitored',monDash.monitored_buckets,'◫','var(--info)'],['Unread',monDash.unread_alerts,'⚠','var(--warning)'],['Critical',monDash.alerts_by_severity?.critical||0,'●','var(--danger)']].map(([l,v,ic,c]:any)=><div key={l} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20,textAlign:'center'}}><div style={{fontSize:24,marginBottom:4}}>{ic}</div><div style={{fontSize:28,fontWeight:800,fontFamily:'var(--font-display)',color:c}}>{v}</div><div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>{l}</div></div>)}</div>}
          <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:24}}>
            <h3 style={{fontSize:15,marginBottom:16}}>Create Watchlist</h3>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NAME</label><input value={wlForm.name} onChange={e=>setWlForm({...wlForm,name:e.target.value})} placeholder="My Company Monitor" style={IS}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>KEYWORDS</label><input value={wlForm.keywords} onChange={e=>setWlForm({...wlForm,keywords:e.target.value})} placeholder="mycompany, myco" style={IS}/></div></div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>COMPANIES</label><input value={wlForm.companies} onChange={e=>setWlForm({...wlForm,companies:e.target.value})} placeholder="company-name" style={IS}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>SCAN EVERY</label><select value={wlForm.interval} onChange={e=>setWlForm({...wlForm,interval:+e.target.value})} style={{...IS,appearance:'auto' as any}}><option value={6}>6 hours</option><option value={12}>12 hours</option><option value={24}>24 hours</option><option value={168}>Weekly</option></select></div></div>
            <div style={{marginBottom:16}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:6}}>PROVIDERS</label>
              <div style={{display:'flex',gap:6}}>{Object.entries(PL).map(([k,l])=>{const a=wlForm.providers.includes(k);return <button key={k} onClick={()=>setWlForm({...wlForm,providers:a?wlForm.providers.filter(p=>p!==k):[...wlForm.providers,k]})} style={{background:a?PC[k].bg+'20':'var(--bg-primary)',border:`1px solid ${a?PC[k].bg:'var(--border-subtle)'}`,borderRadius:8,padding:'4px 10px',cursor:'pointer',color:a?PC[k].bg:'var(--text-muted)',fontSize:11}}>{l as string}</button>})}</div></div>
            <button onClick={createWatchlist} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:'10px 24px',color:'#000',fontWeight:700,cursor:'pointer'}}>+ Create Watchlist</button></div>
          {watchlists.length>0 && <div style={{marginBottom:32}}><h3 style={{fontSize:15,marginBottom:12}}>Active Watchlists</h3>
            {watchlists.map((wl:any)=><div key={wl.id} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20,marginBottom:8,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
              <div><div style={{fontSize:14,fontWeight:600,marginBottom:4}}>{wl.name}</div><div style={{fontSize:11,color:'var(--text-muted)'}}>Keywords: {(typeof wl.keywords==='string'?JSON.parse(wl.keywords):wl.keywords).join(', ')} | Every {wl.scan_interval_hours}h | Last: {ago(wl.last_scan_at)}</div></div>
              <div style={{display:'flex',gap:6}}><button onClick={()=>triggerWlScan(wl.id)} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'5px 12px',borderRadius:8,cursor:'pointer',fontSize:11}}>Scan Now</button><button onClick={()=>deleteWl(wl.id)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'5px 12px',borderRadius:8,cursor:'pointer',fontSize:11}}>Delete</button></div></div>)}</div>}
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:12,flexWrap:'wrap'}}>
            <h3 style={{fontSize:15,margin:0}}>Alerts {alerts?.total?<span style={{fontSize:12,color:'var(--text-muted)'}}>({alerts.total})</span>:null}</h3>
            {monDash?.unread_alerts>0&&<button onClick={markAllAlertsRead} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Mark All Read</button>}
            {aiAvail&&alerts?.items?.length>0&&<button onClick={doPrioritizeAlerts} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'4px 12px',borderRadius:6,cursor:'pointer',color:'#fff',fontSize:10,fontWeight:600}}>✦ AI Prioritize</button>}
            <div style={{display:'flex',gap:4,marginLeft:'auto'}}>{['','critical','high','medium','low','info'].map(s=><button key={s} onClick={()=>{setAlertSevFilter(s);const params=s?`?severity=${s}`:'';apiFetch(`/monitor/alerts${params}`).then(d=>{if(d)setAlerts(d)})}} style={{background:alertSevFilter===s?'var(--bg-tertiary)':'transparent',border:alertSevFilter===s?'1px solid var(--border-default)':'1px solid transparent',color:alertSevFilter===s?'var(--accent)':'var(--text-muted)',padding:'3px 10px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,textTransform:'uppercase' as const}}>{s||'All'}</button>)}</div>
          </div>
          {!alerts?.items?.length ? <div style={{textAlign:'center',padding:40,color:'var(--text-muted)',fontSize:13}}>No alerts yet. Create a watchlist and run a scan.</div>
          : <div style={{display:'flex',flexDirection:'column',gap:4}}>{alerts.items.map((a:any)=><div key={a.id} onClick={()=>!a.is_read&&markAlertRead(a.id)} style={{background:a.is_resolved?'var(--bg-primary)':a.is_read?'var(--bg-secondary)':'var(--bg-tertiary)',border:`1px solid ${a.is_resolved?'var(--border-subtle)':a.is_read?'var(--border-default)':'var(--border-strong)'}`,borderRadius:8,padding:'12px 16px',display:'flex',alignItems:'center',gap:12,cursor:'pointer',opacity:a.is_resolved?0.6:1}}>
            <SevBadge s={a.severity}/><div style={{flex:1,minWidth:0}}><div style={{fontSize:13,fontWeight:a.is_read?400:600,whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis',textDecoration:a.is_resolved?'line-through':'none'}}>{a.title}</div><div style={{fontSize:11,color:'var(--text-muted)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{a.description}</div></div>
            {a.is_resolved?<span style={{fontSize:10,color:'var(--accent)',fontWeight:600}}>✓ Resolved</span>:<button onClick={(e)=>{e.stopPropagation();resolveAlert(a.id)}} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'3px 8px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>Resolve</button>}
            {a.ai_priority_score!=null&&<span style={{background:'#a855f715',border:'1px solid #a855f730',color:'#a855f7',padding:'1px 6px',borderRadius:4,fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>⚡{a.ai_priority_score}</span>}{a.provider_name&&<Badge provider={a.provider_name}/>}<span style={{fontSize:10,color:'var(--text-muted)',whiteSpace:'nowrap' as const}}>{ago(a.created_at)}</span>{!a.is_read&&<div style={{width:8,height:8,borderRadius:'50%',background:'var(--accent)',flexShrink:0}}/>}</div>)}</div>}
          <div style={{marginTop:32}}>
            <h3 style={{fontSize:15,marginBottom:12}}>Webhooks</h3>
            <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:16}}>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NAME</label><input value={whForm.name} onChange={e=>setWhForm({...whForm,name:e.target.value})} placeholder="Slack Alert" style={IS}/></div>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>URL</label><input value={whForm.url} onChange={e=>setWhForm({...whForm,url:e.target.value})} placeholder="https://hooks.slack.com/..." style={IS}/></div></div>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>SECRET (optional)</label><input value={whForm.secret} onChange={e=>setWhForm({...whForm,secret:e.target.value})} placeholder="HMAC signing secret" style={IS}/></div>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:6}}>EVENT TYPES</label>
                  <div style={{display:'flex',gap:6}}>{['critical','high','medium','low'].map(s=>{const a=whForm.event_types.includes(s);return <button key={s} onClick={()=>setWhForm({...whForm,event_types:a?whForm.event_types.filter(e=>e!==s):[...whForm.event_types,s]})} style={{background:a?'var(--accent-bg)':'var(--bg-primary)',border:`1px solid ${a?'rgba(0,232,123,0.3)':'var(--border-subtle)'}`,borderRadius:6,padding:'3px 8px',cursor:'pointer',color:a?'var(--accent)':'var(--text-muted)',fontSize:10,fontWeight:600,textTransform:'uppercase' as const}}>{s}</button>})}</div></div></div>
              <button onClick={createWebhook} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:'8px 20px',color:'#000',fontWeight:700,cursor:'pointer',fontSize:12}}>+ Add Webhook</button></div>
            {webhooks.length>0 && webhooks.map((wh:any)=><div key={wh.id} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:'14px 20px',marginBottom:8,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}><span style={{fontSize:13,fontWeight:600}}>{wh.name}</span><span style={{width:8,height:8,borderRadius:'50%',background:wh.is_active?'var(--accent)':'var(--text-muted)'}}/>{wh.failure_count>0&&<span style={{fontSize:10,color:'var(--danger)'}}>Failures: {wh.failure_count}</span>}</div>
                <div style={{fontSize:11,color:'var(--text-muted)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{wh.url.replace(/^https?:\/\//,'').slice(0,50)}... | {(() => { try { return (typeof wh.event_types==='string'?JSON.parse(wh.event_types):wh.event_types).join(', ') } catch { return '' } })()} | Last: {ago(wh.last_triggered)}</div></div>
              <div style={{display:'flex',gap:6}}><button onClick={()=>testWebhook(wh.id)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'4px 10px',borderRadius:6,cursor:'pointer',fontSize:10}}>Test</button><button onClick={()=>toggleWebhook(wh.id,!wh.is_active)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:wh.is_active?'var(--warning)':'var(--accent)',padding:'4px 10px',borderRadius:6,cursor:'pointer',fontSize:10}}>{wh.is_active?'Pause':'Enable'}</button><button onClick={()=>deleteWebhook(wh.id)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'4px 10px',borderRadius:6,cursor:'pointer',fontSize:10}}>Delete</button></div></div>)}
          </div>
        </>}</div>}

      {/* ─── AI INSIGHTS ─── */}
      {view==='ai-insights' && <div style={{padding:'80px 24px 24px',maxWidth:1100,margin:'0 auto'}}>
        <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:8}}><h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>✦ AI Insights</h2>
          <span style={{background:aiAvail?'#a855f715':'var(--bg-tertiary)',border:`1px solid ${aiAvail?'#a855f730':'var(--border-subtle)'}`,color:aiAvail?'#a855f7':'var(--text-muted)',padding:'2px 10px',borderRadius:6,fontSize:10,fontWeight:600}}>{aiAvail?'AI Active':'AI Unavailable'}</span>
          {aiProviders.length>0&&<select value={aiProvider} onChange={e=>doSwitchProvider(e.target.value)} disabled={providerSwitching} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'4px 8px',color:'var(--text-secondary)',fontSize:11,fontFamily:'var(--font-mono)',cursor:'pointer',opacity:providerSwitching?0.5:1}}>
            {aiProviders.map((p:any)=><option key={p.name} value={p.name} disabled={!p.available}>{p.display_name}{!p.available?' (unavailable)':''}</option>)}
          </select>}</div>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:32}}>AI-powered analysis of your cloud storage security posture.</p>

        {/* AI Status Card */}
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12,marginBottom:32}}>
          <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20,textAlign:'center'}}>
            <div style={{fontSize:24,marginBottom:4}}>✦</div><div style={{fontSize:28,fontWeight:800,fontFamily:'var(--font-display)',color:'#a855f7'}}>{aiAvail?'ON':'OFF'}</div><div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>{aiAvail&&aiProvider?aiProviders.find((p:any)=>p.name===aiProvider)?.display_name||'AI Engine':'AI Engine'}</div></div>
          <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20,textAlign:'center'}}>
            <div style={{fontSize:24,marginBottom:4}}>🛡</div><div style={{fontSize:28,fontWeight:800,fontFamily:'var(--font-display)',color:'var(--accent)'}}>{stats?.total_buckets||0}</div><div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>Buckets Indexed</div></div>
          <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:20,textAlign:'center'}}>
            <div style={{fontSize:24,marginBottom:4}}>⬡</div><div style={{fontSize:28,fontWeight:800,fontFamily:'var(--font-display)',color:'var(--info)'}}>{stats?.total_files||0}</div><div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>Files Scanned</div></div>
        </div>

        {/* NL Search */}
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:24}}>
          <h3 style={{fontSize:15,marginBottom:12,display:'flex',alignItems:'center',gap:8}}>✦ Natural Language Search</h3>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:12}}>Search your indexed files using plain English queries.</p>
          <div style={{display:'flex',gap:8}}><input value={nlQuery} onChange={e=>setNlQuery(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doNlSearch(nlQuery)} placeholder="Find SQL backups in AWS that are larger than 1MB..." style={{...IS,flex:1,border:'1px solid #a855f730'}}/>
            <button onClick={()=>doNlSearch(nlQuery)} disabled={!nlQuery.trim()||sLoading} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'10px 20px',borderRadius:8,cursor:!nlQuery.trim()?'not-allowed':'pointer',color:'#fff',fontSize:12,fontWeight:600,opacity:!nlQuery.trim()?0.5:1}}>{sLoading?'...':'Search'}</button></div>
          {nlParsed&&<div style={{marginTop:12,display:'flex',gap:6,flexWrap:'wrap'}}>{Object.entries(nlParsed).filter(([,v])=>v).map(([k,v]:any)=><span key={k} style={{background:'#a855f710',border:'1px solid #a855f730',color:'#a855f7',padding:'2px 8px',borderRadius:4,fontSize:10}}>
            {k}: {typeof v==='object'?JSON.stringify(v):String(v)}</span>)}</div>}
        </div>

        {/* Security Report */}
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:24}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}><h3 style={{fontSize:15,margin:0,display:'flex',alignItems:'center',gap:8}}>✦ Security Report</h3>
            <button onClick={doGenReport} disabled={aiReportLoading||!aiAvail} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'6px 16px',borderRadius:6,cursor:aiReportLoading||!aiAvail?'not-allowed':'pointer',color:'#fff',fontSize:11,fontWeight:600,opacity:aiReportLoading||!aiAvail?0.5:1}}>{aiReportLoading?'Generating...':'✦ Generate Report'}</button></div>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:12}}>Generate an AI-powered executive summary of your cloud storage security posture.</p>
          {aiReport && <div style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:20}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
              <span style={{fontSize:13,fontWeight:600,color:'var(--text-secondary)'}}>Security Report</span>
              <span style={{fontSize:10,color:'var(--text-muted)'}}>Generated {aiReport.generated_at?new Date(aiReport.generated_at).toLocaleString():''}</span></div>
            <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:12}}>Total Buckets: {aiReport.total_buckets} | Open Buckets: {aiReport.open_buckets} | High Risk: {aiReport.high_risk_count}</div>
            <div style={{fontSize:13,color:'var(--text-secondary)',whiteSpace:'pre-wrap' as const,lineHeight:1.7}}>{aiReport.report}</div>
          </div>}
        </div>

        {/* Classification Overview */}
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24}}>
          <h3 style={{fontSize:15,marginBottom:12,display:'flex',alignItems:'center',gap:8}}>✦ File Classification Overview</h3>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:16}}>AI-assigned sensitivity categories across all indexed files.</p>
          {aiClassSummary && Object.keys(aiClassSummary).length>0 ? <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:12}}>
            {Object.entries(aiClassSummary).map(([cat,cnt]:any)=><div key={cat} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:16,display:'flex',alignItems:'center',gap:10}}>
              <ClassBadge c={cat}/><span style={{fontSize:20,fontWeight:700,fontFamily:'var(--font-display)',color:'var(--text-secondary)'}}>{cnt}</span><span style={{fontSize:11,color:'var(--text-muted)'}}>files</span></div>)}
          </div> : <div style={{textAlign:'center',padding:32,color:'var(--text-muted)',fontSize:12}}>No classified files yet. Use AI Analyze on a bucket to classify its files.</div>}
        </div>
      </div>}

      {/* ─── SETTINGS ─── */}
      {view==='settings' && user && <div style={{padding:'80px 24px 24px',maxWidth:600,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:24}}>Account Settings</h2>
        {settingsMsg&&<div style={{background:settingsMsg.includes('fail')||settingsMsg.includes('match')?'rgba(240,72,72,0.1)':'var(--accent-bg)',border:`1px solid ${settingsMsg.includes('fail')||settingsMsg.includes('match')?'rgba(240,72,72,0.2)':'rgba(0,232,123,0.2)'}`,borderRadius:8,padding:'8px 16px',marginBottom:16,fontSize:12,color:settingsMsg.includes('fail')||settingsMsg.includes('match')?'var(--danger)':'var(--accent)'}}>{settingsMsg}</div>}
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:16}}>
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Account Info</h3>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
            {[['Email',user.email],['Username',user.username],['Tier',user.tier?.toUpperCase()],['Member Since',user.created_at?new Date(user.created_at).toLocaleDateString():'—'],['Last Login',ago(user.last_login)],['Queries Today',user.queries_today||0]].map(([l,v]:any)=><div key={l} style={{padding:12,background:'var(--bg-primary)',borderRadius:8,border:'1px solid var(--border-subtle)'}}><div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4,textTransform:'uppercase' as const}}>{l}</div><div style={{fontSize:13,color:'var(--text-primary)',fontWeight:600}}>{v}</div></div>)}
          </div>
        </div>
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24,marginBottom:16}}>
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>API Key</h3>
          <div style={{display:'flex',alignItems:'center',gap:12}}>
            <div style={{flex:1,background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'10px 14px',fontFamily:'var(--font-mono)',fontSize:12,color:'var(--text-secondary)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{showApiKey?user.api_key:'cs_••••••••••••••••••••••••••••••'}</div>
            <button onClick={()=>setShowApiKey(!showApiKey)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:11}}>{showApiKey?'Hide':'Show'}</button>
            <button onClick={()=>{navigator.clipboard.writeText(user.api_key);setCopiedKey(true);setTimeout(()=>setCopiedKey(false),2000)}} style={{background:copiedKey?'var(--accent-bg)':'var(--bg-primary)',border:`1px solid ${copiedKey?'rgba(0,232,123,0.3)':'var(--border-subtle)'}`,color:copiedKey?'var(--accent)':'var(--text-muted)',padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:11,transition:'all 0.2s'}}>{copiedKey?'Copied!':'Copy'}</button>
            <button onClick={rotateApiKey} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--warning)',padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:11}}>Rotate</button>
          </div>
        </div>
        <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:24}}>
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Update Profile</h3>
          <div style={{marginBottom:12}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NEW USERNAME</label>
            <input value={settingsForm.username} onChange={e=>setSettingsForm({...settingsForm,username:e.target.value})} placeholder={user.username} style={IS}/></div>
          <div style={{marginBottom:12}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NEW PASSWORD</label>
            <input type="password" value={settingsForm.password} onChange={e=>setSettingsForm({...settingsForm,password:e.target.value})} placeholder="Leave blank to keep current" style={IS}/></div>
          <div style={{marginBottom:16}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>CONFIRM PASSWORD</label>
            <input type="password" value={settingsForm.confirmPassword} onChange={e=>setSettingsForm({...settingsForm,confirmPassword:e.target.value})} placeholder="Confirm new password" style={IS}/></div>
          <button onClick={updateSettings} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:'10px 24px',color:'#000',fontWeight:700,cursor:'pointer',fontSize:12}}>Save Changes</button>
        </div>
      </div>}

      {/* ─── ACTIVITY LOG ─── */}
      {view==='activity' && <div style={{padding:'80px 24px 24px',maxWidth:1000,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Activity Log</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24}}>Your API request history.</p>
        {!user ? <div style={{textAlign:'center',padding:40,color:'var(--text-muted)',fontSize:13}}>Sign in to view your activity log.</div>
        : !activity?.items?.length ? <div style={{textAlign:'center',padding:40,color:'var(--text-muted)',fontSize:13}}>No activity recorded yet.</div>
        : <>
          <div style={{display:'grid',gridTemplateColumns:'60px 1fr 50px 60px 100px',gap:12,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}><span>Method</span><span>Endpoint</span><span>Status</span><span>Time</span><span>When</span></div>
          {activity.items.map((a:any,i:number)=>{const mc:any={GET:'var(--accent)',POST:'var(--info)',PUT:'var(--warning)',DELETE:'var(--danger)'};return <div key={a.id||i} style={{display:'grid',gridTemplateColumns:'60px 1fr 50px 60px 100px',gap:12,padding:'10px 16px',alignItems:'center',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4}}>
            <span style={{fontSize:10,fontWeight:700,color:mc[a.method]||'var(--text-muted)'}}>{a.method}</span>
            <span style={{fontSize:11,color:'var(--text-secondary)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{a.endpoint}</span>
            <span style={{fontSize:10,fontWeight:600,color:a.response_status<400?'var(--accent)':a.response_status<500?'var(--warning)':'var(--danger)'}}>{a.response_status}</span>
            <span style={{fontSize:10,color:'var(--text-muted)'}}>{a.response_time_ms!=null?`${a.response_time_ms}ms`:'—'}</span>
            <span style={{fontSize:10,color:'var(--text-muted)'}}>{ago(a.created_at)}</span>
          </div>})}
          {activity.total>50&&<div style={{display:'flex',justifyContent:'center',gap:8,marginTop:16}}>
            <button disabled={activityPage<=1} onClick={()=>loadActivity(activityPage-1)} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'6px 14px',cursor:activityPage<=1?'not-allowed':'pointer',color:'var(--text-secondary)',fontSize:12,opacity:activityPage<=1?0.5:1}}>Prev</button>
            <span style={{padding:'6px 14px',fontSize:12,color:'var(--text-muted)'}}>Page {activityPage} of {Math.ceil(activity.total/50)}</span>
            <button disabled={activityPage>=Math.ceil(activity.total/50)} onClick={()=>loadActivity(activityPage+1)} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'6px 14px',cursor:activityPage>=Math.ceil(activity.total/50)?'not-allowed':'pointer',color:'var(--text-secondary)',fontSize:12,opacity:activityPage>=Math.ceil(activity.total/50)?0.5:1}}>Next</button>
          </div>}
        </>}
      </div>}

      {/* ─── API DOCS ─── */}
      {view==='api-docs' && <div style={{padding:'80px 24px 24px',maxWidth:900,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>REST API</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:32}}>Bearer token or API key auth. SSE for real-time events.</p>
        {[{m:'GET',p:'/api/v1/files',d:'Full-text + regex file search'},{m:'GET',p:'/api/v1/files/export',d:'Export results as CSV/JSON'},{m:'GET',p:'/api/v1/files/:id/preview',d:'Preview file contents (4KB)'},{m:'POST',p:'/api/v1/searches/saved',d:'Save a search'},{m:'GET',p:'/api/v1/searches/saved',d:'List saved searches'},{m:'DELETE',p:'/api/v1/searches/saved/:id',d:'Delete saved search'},{m:'GET',p:'/api/v1/stats/timeline',d:'Discovery timeline (30d)'},{m:'GET',p:'/api/v1/stats/breakdown',d:'Analytics breakdown'},{m:'GET',p:'/api/v1/buckets',d:'List buckets'},{m:'GET',p:'/api/v1/stats',d:'Database stats'},{m:'GET',p:'/api/v1/events/scans',d:'SSE scan stream'},{m:'POST',p:'/api/v1/scans',d:'Start discovery scan'},{m:'POST',p:'/api/v1/auth/register',d:'Create account'},{m:'POST',p:'/api/v1/auth/login',d:'Login'},{m:'POST',p:'/api/v1/monitor/watchlists',d:'Create watchlist'},{m:'GET',p:'/api/v1/monitor/alerts',d:'List alerts'},{m:'GET',p:'/api/v1/monitor/dashboard',d:'Monitor dashboard'},{m:'POST',p:'/api/v1/monitor/webhooks',d:'Create webhook'},{m:'GET',p:'/api/v1/monitor/webhooks',d:'List webhooks'},{m:'PUT',p:'/api/v1/monitor/webhooks/:id',d:'Update webhook'},{m:'DELETE',p:'/api/v1/monitor/webhooks/:id',d:'Delete webhook'},{m:'POST',p:'/api/v1/monitor/webhooks/:id/test',d:'Test webhook'},{m:'GET',p:'/api/v1/ai/status',d:'AI availability status',ai:true},{m:'POST',p:'/api/v1/ai/classify/:id',d:'Classify bucket files',ai:true},{m:'GET',p:'/api/v1/ai/classifications',d:'Classification summary',ai:true},{m:'POST',p:'/api/v1/ai/risk/:id',d:'Calculate risk score',ai:true},{m:'POST',p:'/api/v1/ai/search',d:'Natural language search',ai:true},{m:'POST',p:'/api/v1/ai/report',d:'Generate security report',ai:true},{m:'POST',p:'/api/v1/ai/suggest-keywords',d:'Smart keyword suggestions',ai:true},{m:'POST',p:'/api/v1/ai/prioritize-alerts',d:'Prioritize alerts with AI',ai:true}].map((ep:any)=><div key={ep.p+ep.m} style={{background:'var(--bg-secondary)',border:`1px solid ${ep.ai?'#a855f720':'var(--border-default)'}`,borderRadius:12,padding:16,marginBottom:8,display:'flex',alignItems:'center',gap:10}}>
          <span style={{background:ep.m==='GET'?'var(--accent-bg)':'#ff990015',color:ep.m==='GET'?'var(--accent)':'var(--aws)',padding:'2px 8px',borderRadius:4,fontSize:11,fontWeight:700,border:`1px solid ${ep.m==='GET'?'rgba(0,232,123,0.2)':'rgba(255,153,0,0.2)'}`}}>{ep.m}</span>
          <span style={{fontSize:13,fontWeight:600}}>{ep.p}</span><span style={{fontSize:12,color:'var(--text-tertiary)'}}>{ep.d}</span>{ep.ai&&<span style={{background:'#a855f715',border:'1px solid #a855f730',color:'#a855f7',padding:'1px 6px',borderRadius:4,fontSize:9,fontWeight:600}}>AI</span>}</div>)}</div>}
    </div>
  )
}