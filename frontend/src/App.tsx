import { useState, useEffect, useCallback, useRef } from 'react'
import { API_BASE } from './config'

const API = API_BASE
const fmt = (b:number) => { if(!b) return '0 B'; const k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(1))+' '+s[i] }
const fnum = (n:number) => n ? n.toLocaleString() : '0'
const ago = (d:string) => { if(!d) return '—'; const s=Math.floor((Date.now()-new Date(d).getTime())/1000); if(s<60) return s+'s ago'; if(s<3600) return Math.floor(s/60)+'m ago'; if(s<86400) return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago' }
const PC:any = { aws:{bg:'#ff9900',t:'#000'}, azure:{bg:'#0078d4',t:'#fff'}, gcp:{bg:'#4285f4',t:'#fff'}, digitalocean:{bg:'#0080ff',t:'#fff'}, alibaba:{bg:'#ff6a00',t:'#fff'} }
const PL:any = { aws:'AWS S3', azure:'Azure Blob', gcp:'GCP Storage', digitalocean:'DO Spaces', alibaba:'Alibaba OSS' }
const EI:any = { sql:'🗄️',csv:'📊',json:'📋',yaml:'⚙️',yml:'⚙️',xml:'📄',pdf:'📕',docx:'📘',xlsx:'📗',zip:'📦',gz:'📦',env:'🔑',key:'🔐',pem:'🔐',pub:'🔐',sh:'🖥️',py:'🐍',js:'📜',css:'🎨',html:'🌐',log:'📝',md:'📝',ini:'⚙️',tfstate:'🏗️',bak:'💾',sqlite:'🗄️',parquet:'📊',php:'🐘' }
const IS = {width:'100%' as const,boxSizing:'border-box' as const,background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'10px 14px',color:'var(--text-primary)',fontSize:13,fontFamily:'var(--font-body)'}

let _token: string | null = null
try { _token = localStorage.getItem('cs_token') } catch{}
let _csrfToken: string | null = null
const fetchCsrfToken = async () => {
  if(_csrfToken) return _csrfToken
  try {
    const headers: any = {'Content-Type':'application/json'}
    if(_token) headers['Authorization'] = `Bearer ${_token}`
    const r = await fetch(`${API}/csrf-token`,{headers})
    if(r.ok) { const d = await r.json(); _csrfToken = d.csrf_token }
  } catch{}
  return _csrfToken
}
const apiFetch = async (ep:string, opts:any={}) => {
  try {
    const method = (opts.method || 'GET').toUpperCase()
    const headers: any = {'Content-Type':'application/json', ...opts.headers}
    if(_token) headers['Authorization'] = `Bearer ${_token}`
    if(['POST','PUT','DELETE'].includes(method)) {
      const csrf = await fetchCsrfToken()
      if(csrf) { headers['X-CSRF-Token'] = csrf; _csrfToken = null }
    }
    const r = await fetch(`${API}${ep}`,{...opts, headers})
    if(r.status === 401) { _token = null; _csrfToken = null; try{localStorage.removeItem('cs_token')}catch{} }
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
const Attribution = ({bucket:b}:{bucket:any}) => { if(!b?.company_name)return null; const verified=b.ownership_status==='verified'; const confidence=b.attribution_confidence!=null?` · ${Math.round(b.attribution_confidence*100)}% confidence`:''; return <div style={{fontSize:10,color:verified?'var(--accent)':'var(--info)',fontWeight:600,marginTop:2}} title={`${b.attribution_source||'legacy attribution'}${confidence}. ${verified?'Ownership verified.':'Ownership has not been verified.'}`}>{b.company_name} <span style={{fontSize:8,color:'var(--text-muted)',fontWeight:400,fontStyle:'italic'}}>{verified?'verified':`inferred${confidence}`}</span></div> }
const ExposureBadge = ({type}:{type:string}) => { const labels:any={public_listing:'PUBLIC LISTING',public_website:'PUBLIC WEBSITE',access_denied:'ACCESS DENIED',existence_only:'EXISTS',unknown:'UNVERIFIED'}; return <span style={{fontSize:9,color:type?.startsWith('public_')?'var(--accent)':'var(--text-muted)',fontWeight:700,fontFamily:'var(--font-mono)'}}>{labels[type]||String(type||'unknown').toUpperCase()}</span> }

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
        {e.bucket?.company_name && <Attribution bucket={e.bucket}/>}
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
  // Sprint 4 state
  const [notifCount, setNotifCount] = useState(0)
  const [notifications, setNotifications] = useState<any[]>([])
  const [showNotifPanel, setShowNotifPanel] = useState(false)
  const [orgs, setOrgs] = useState<any[]>([])
  const [activeOrg, setActiveOrg] = useState<any>(null)
  const [orgMembers, setOrgMembers] = useState<any[]>([])
  const [complianceFrameworks, setComplianceFrameworks] = useState<any[]>([])
  const [complianceDashboard, setComplianceDashboard] = useState<any>(null)
  const [complianceResults, setComplianceResults] = useState<any[]>([])
  const [selectedFramework, setSelectedFramework] = useState<any>(null)
  const [remediations, setRemediations] = useState<any>({items:[], total:0})
  const [remDashboard, setRemDashboard] = useState<any>({})
  const [reports, setReports] = useState<any>({items:[], total:0})
  const [reportSchedules, setReportSchedules] = useState<any[]>([])
  const [integrations, setIntegrations] = useState<any[]>([])
  // Sprint 5 state
  const [tags, setTags] = useState<any[]>([])
  const [bookmarkIds, setBookmarkIds] = useState<number[]>([])
  const [scanSchedules, setScanSchedules] = useState<any[]>([])
  const [auditLog, setAuditLog] = useState<any>({items:[], total:0})
  const [advFilters, setAdvFilters] = useState({date_from:'',date_to:'',min_size:'',max_size:''})
  const [showAdvFilters, setShowAdvFilters] = useState(false)
  const [bulkAlerts, setBulkAlerts] = useState<number[]>([])
  const [bulkRems, setBulkRems] = useState<number[]>([])
  const [tagForm, setTagForm] = useState({name:'',color:'#6b7280'})
  const [schedForm, setSchedForm] = useState({name:'',keywords:'',companies:'',frequency:'daily',providers:[] as string[]})
  const [showTagPicker, setShowTagPicker] = useState<number|null>(null)
  const [bucketSearch, setBucketSearch] = useState('')
  const [bucketStatusFilter, setBucketStatusFilter] = useState('')
  const [bucketProviderFilter, setBucketProviderFilter] = useState('')
  const [expandedApi, setExpandedApi] = useState<string|null>(null)
  const [apiFilterTag, setApiFilterTag] = useState('')
  const [apiSearchQ, setApiSearchQ] = useState('')
  const [navDropdown, setNavDropdown] = useState<string|null>(null)
  // Sprint 6 state: 2FA, Drift, Alert Rules, Dashboard
  const [twoFaStatus, setTwoFaStatus] = useState<any>(null)
  const [twoFaSetup, setTwoFaSetup] = useState<any>(null)
  const [twoFaCode, setTwoFaCode] = useState('')
  const [twoFaTempToken, setTwoFaTempToken] = useState('')
  const [driftDiffs, setDriftDiffs] = useState<any>({items:[], total:0})
  const [driftSummary, setDriftSummary] = useState<any>(null)
  const [driftFilter, setDriftFilter] = useState({severity:'',unreviewed:false})
  const [alertRules, setAlertRules] = useState<any[]>([])
  const [ruleForm, setRuleForm] = useState({name:'',description:'',severity:'medium',conditions:[] as any[],condType:'file_extension',condValue:''})
  const [execDash, setExecDash] = useState<any>(null)
  const [riskTrends, setRiskTrends] = useState<any>(null)
  const [remSla, setRemSla] = useState<any>(null)
  // Sprint 7 state: 20 new features
  const [featView, setFeatView] = useState('overview')
  const [industryData, setIndustryData] = useState<any[]>([])
  const [trendData, setTrendData] = useState<any>(null)
  const [attackSurface, setAttackSurface] = useState<any>(null)
  const [sensitiveFindings, setSensitiveFindings] = useState<any>({findings:[], count:0})
  const [sensitiveSummary, setSensitiveSummary] = useState<any>(null)
  const [compViolations, setCompViolations] = useState<any>(null)
  const [breachTimeline, setBreachTimeline] = useState<any>(null)
  const [execReport, setExecReport] = useState<any>(null)
  const [tickets, setTickets] = useState<any[]>([])
  const [takedownGuide, setTakedownGuide] = useState<any>(null)
  const [benchmarkData, setBenchmarkData] = useState<any>(null)
  const [benchmarkCompany, setBenchmarkCompany] = useState('')
  const [patternSearch, setPatternSearch] = useState('')
  const [patternResults, setPatternResults] = useState<any[]>([])
  const [subdomainDomain, setSubdomainDomain] = useState('')
  const [subdomainNames, setSubdomainNames] = useState<string[]>([])
  const [codeText, setCodeText] = useState('')
  const [codeRefs, setCodeRefs] = useState<any[]>([])
  const [siemEvents, setSiemEvents] = useState<any[]>([])
  // Quick wins: toast, modal, loading, shortcuts
  const [toasts, setToasts] = useState<{id:number,msg:string,type:string}[]>([])
  const toast = useCallback((msg:string,type='info')=>{const id=Date.now();setToasts(p=>[...p,{id,msg,type}]);setTimeout(()=>setToasts(p=>p.filter(t=>t.id!==id)),3500)},[])
  const [modal, setModal] = useState<{title:string,msg:string,onConfirm:()=>void,input?:boolean}|null>(null)
  const [modalInput, setModalInput] = useState('')
  const [actionLoading, setActionLoading] = useState<string|null>(null)
  const loadStats = useCallback(() => {
    apiFetch('/stats', {cache:'no-store'}).then(d => {
      if(d?.total_buckets !== undefined) setStats(d)
    })
  }, [])

  useEffect(()=>{ document.documentElement.setAttribute('data-theme',theme); try{localStorage.setItem('cs_theme',theme)}catch{} },[theme])
  useEffect(()=>{ try{localStorage.setItem('cs_onboarding',JSON.stringify(onboarding))}catch{} },[onboarding])
  useEffect(()=>{window.scrollTo(0,0)},[view])
  useEffect(()=>{const h=(e:KeyboardEvent)=>{if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();setView('search');setTimeout(()=>ref.current?.focus(),100)};if(e.key==='Escape'){setShowNotifPanel(false);setModal(null);setBulkAlerts([]);setBulkRems([])}};window.addEventListener('keydown',h);return()=>window.removeEventListener('keydown',h)},[])

  useEffect(() => {
    loadStats()
    const interval = window.setInterval(loadStats, 60_000)
    const refreshWhenVisible = () => {
      if(document.visibilityState === 'visible') loadStats()
    }
    window.addEventListener('focus', loadStats)
    document.addEventListener('visibilitychange', refreshWhenVisible)
    return () => {
      window.clearInterval(interval)
      window.removeEventListener('focus', loadStats)
      document.removeEventListener('visibilitychange', refreshWhenVisible)
    }
  }, [loadStats])
  useEffect(() => { apiFetch('/ai/status').then(d => { if(d){setAiAvail(d.available||false);setAiProvider(d.active_provider||'');setAiProviders(d.providers||[])} }); apiFetch('/stats/timeline?days=30').then(d=>d&&setDashTimeline(d)); apiFetch('/stats/breakdown').then(d=>d&&setDashBreakdown(d)) }, [])
  useEffect(() => { if(_token) { apiFetch('/auth/me').then(d => { if(d?.id) setUser(d); else { _token=null; try{localStorage.removeItem('cs_token')}catch{} } }); apiFetch('/searches/saved').then(d=>{if(d?.items)setSavedSearches(d.items)}); loadNotifCount(); loadOrgs() } const notifInterval = setInterval(() => { if(_token) loadNotifCount() }, 30000); return () => clearInterval(notifInterval) }, [])

  const connectSSE = useCallback(() => {
    if(sseCleanup.current) sseCleanup.current()
    if(!_token) return
    const es = new EventSource(`${API}/events/scans?access_token=${encodeURIComponent(_token)}`)
    es.addEventListener('connected',() => setSseConnected(true))
    es.addEventListener('progress',(e:any) => setScanProgress(JSON.parse(e.data)))
    es.addEventListener('bucket_found',(e:any) => { const d=JSON.parse(e.data); setScanEvents(prev=>[...prev,d]) })
    es.addEventListener('scan_complete',(e:any) => { const d=JSON.parse(e.data); setScanProgress((p:any)=>({...p,...d.stats,phase:'complete'})); loadStats() })
    es.addEventListener('scan_started',(e:any) => { setScanEvents([]); setScanProgress({phase:'scanning',...JSON.parse(e.data)}) })
    es.onerror = () => setSseConnected(false); sseCleanup.current = () => es.close(); return () => es.close()
  },[loadStats])
  useEffect(() => { const c = connectSSE(); return c }, [connectSSE])

  const doLogin = async() => { setAuthError(''); setAuthSuccess(''); setAuthLoading(true); const r = await apiFetch('/auth/login',{method:'POST',body:JSON.stringify({email:authForm.email,password:authForm.password})}); setAuthLoading(false); if(!r){setAuthError('Login failed');return}; if(r.requires_2fa){setTwoFaTempToken(r.temp_token);setAuthMode('login' as any);setAuthSuccess('Enter your 2FA code');setTwoFaCode('');return}; if(!r.token){setAuthError(r?.error||'Invalid credentials');return}; _token=r.token; _csrfToken=null; try{localStorage.setItem('cs_token',r.token)}catch{}; setUser(r.user); setView('home'); setAuthForm({email:'',username:'',password:''}) }
  const doVerify2fa = async() => { setAuthError(''); setAuthLoading(true); const r = await apiFetch('/auth/2fa/verify',{method:'POST',body:JSON.stringify({temp_token:twoFaTempToken,code:twoFaCode})}); setAuthLoading(false); if(!r||!r.token){setAuthError(r?.error||'Invalid code');return}; _token=r.token; _csrfToken=null; try{localStorage.setItem('cs_token',r.token)}catch{}; setUser(r.user); setView('home'); setTwoFaTempToken(''); setTwoFaCode(''); setAuthForm({email:'',username:'',password:''}) }
  const doRegister = async() => { setAuthError(''); setAuthSuccess(''); setAuthLoading(true); const r = await apiFetch('/auth/register',{method:'POST',body:JSON.stringify(authForm)}); setAuthLoading(false); if(!r||!r.token){setAuthError(r?.error||'Registration failed');return}; _token=r.token; _csrfToken=null; try{localStorage.setItem('cs_token',r.token)}catch{}; setUser(r.user); setShowWelcome(true); setView('home'); setAuthForm({email:'',username:'',password:''}) }
  const doLogout = () => { _token=null; _csrfToken=null; try{localStorage.removeItem('cs_token')}catch{}; setUser(null); setView('home'); setAuthMode('login'); setAuthError(''); setAuthSuccess('') }
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
    _token=r.token; _csrfToken=null; try{localStorage.setItem('cs_token',r.token)}catch{}
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
  const testWebhook = async(id:number) => { const r = await apiFetch(`/monitor/webhooks/${id}/test`,{method:'POST'}); toast(r?.success?'Webhook test sent!':'Webhook test failed: '+(r?.error||'Unknown'),r?.success?'success':'error') }
  const doSaveSearch = async() => { if(!saveSearchName.trim()||!sq.trim())return; const params:any={q:regexMode?'':sq,regex:regexMode?sq:'',ext:sf.ext,provider:sf.provider,sort:sf.sort,regexMode}; await apiFetch('/searches/saved',{method:'POST',body:JSON.stringify({name:saveSearchName,query_params:params})}); setSaveSearchName(''); const d=await apiFetch('/searches/saved'); if(d?.items)setSavedSearches(d.items) }
  const doLoadSavedSearch = (item:any) => { try{const p=typeof item.query_params==='string'?JSON.parse(item.query_params):item.query_params; setSq(p.regex||p.q||''); setRegexMode(!!p.regexMode); setSf({ext:p.ext||'',provider:p.provider||'',sort:p.sort||'relevance',page:1}); setShowSavedDropdown(false); doSearch(p.regex||p.q||'',{ext:p.ext||'',provider:p.provider||'',sort:p.sort||'relevance',page:1},!!p.regexMode)}catch{} }
  const doDeleteSavedSearch = async(id:number) => { await apiFetch(`/searches/saved/${id}`,{method:'DELETE'}); const d=await apiFetch('/searches/saved'); if(d?.items)setSavedSearches(d.items) }
  const doPreview = async(fileId:number) => { if(previewFile===fileId){setPreviewFile(null);setPreviewData(null);return} setPreviewFile(fileId); setPreviewLoading(true); const d=await apiFetch(`/files/${fileId}/preview`); setPreviewData(d); setPreviewLoading(false) }

  const doSearch = useCallback(async(q:string, f:any=sf, useRegex:boolean=regexMode, af:any=advFilters) => { if(!q.trim())return; setSLoading(true); setView('search'); setSq(q); const p:any={...f}; if(useRegex){p.regex=q}else{p.q=q} if(af.date_from)p.date_from=af.date_from; if(af.date_to)p.date_to=af.date_to; if(af.min_size)p.min_size=af.min_size; if(af.max_size)p.max_size=af.max_size; Object.keys(p).forEach((k:string)=>!p[k]&&delete p[k]); const qs=new URLSearchParams(p).toString(); const d=await apiFetch(`/files?${qs}`); setSr(d||{items:[],total:0,page:1,per_page:50,query:q,response_time_ms:0}); setSLoading(false); setOnboarding(o=>({...o,firstSearch:true})) },[sf,regexMode,advFilters])
  const loadBk = useCallback(async(f:any={}) => { const params:any={...f}; if(!params.search && bucketSearch) params.search=bucketSearch; if(!params.provider && bucketProviderFilter) params.provider=bucketProviderFilter; if(!params.status && bucketStatusFilter) params.status=bucketStatusFilter; Object.keys(params).forEach(k=>{if(!params[k])delete params[k]}); const qs=new URLSearchParams(params).toString(); setBuckets(await apiFetch(`/buckets?${qs}`)||{items:[],total:0,page:1}); setView('buckets'); loadBookmarkIds(); loadTags() },[bucketSearch,bucketProviderFilter,bucketStatusFilter])
  const loadBd = useCallback(async(id:number) => { setBd(await apiFetch(`/buckets/${id}`)||null); setView('bucket-detail') },[])
  const startScan = async() => {
    const d:any={keywords:scanForm.keywords.split(',').map((s:string)=>s.trim()).filter(Boolean),companies:scanForm.companies.split(',').map((s:string)=>s.trim()).filter(Boolean)}
    if(scanForm.providers.length)d.providers=scanForm.providers; if(!d.keywords.length&&!d.companies.length)return toast('Enter at least one keyword or company name','error')
    if(!sseConnected)connectSSE(); setScanProgress({phase:'starting',names_total:0,names_checked:0,buckets_found:0,buckets_open:0,files_indexed:0,errors:0}); setScanEvents([])
    const r=await apiFetch('/scans',{method:'POST',body:JSON.stringify(d)}); setScanStatus(r)
    if(r?.id){const pollId=setInterval(async()=>{const job=await apiFetch(`/scans/${r.id}`);if(!job)return;if(job.progress){try{setScanProgress(typeof job.progress==='string'?JSON.parse(job.progress):job.progress)}catch{}}
      setScanProgress((prev:any)=>({...prev,names_checked:job.names_checked||prev?.names_checked||0,buckets_found:job.buckets_found||prev?.buckets_found||0,buckets_open:job.buckets_open||prev?.buckets_open||0,files_indexed:job.files_indexed||prev?.files_indexed||0,phase:job.status==='completed'?'complete':job.status==='failed'?'failed':job.status==='cancelled'?'cancelled':prev?.phase||'scanning'}))
      if(job.status==='completed'||job.status==='failed'||job.status==='cancelled'){clearInterval(pollId);loadStats();loadScanHistory();if(job.status==='completed')setOnboarding(o=>({...o,firstScan:true}));if(job.status==='cancelled')setScanProgress(null)}},2000)}
  }

  // ── Nav navigation helper ──
  const navGo=(id:string)=>{setNavDropdown(null);if(id==='buckets')loadBk();else if(id==='search'){setView('search');setTimeout(()=>ref.current?.focus(),100)}else if(id==='monitor')loadMonitor();else if(id==='compliance'){setView('compliance');loadComplianceDashboard();loadComplianceFrameworks()}else if(id==='remediate'){setView('remediate');loadRemDashboard();loadRemediations()}else if(id==='ai-insights'){setView('ai-insights');apiFetch('/ai/classifications').then(d=>{if(d?.summary)setAiClassSummary(d.summary)})}else if(id==='scan'){setView('scan');loadScanHistory();loadScanSchedules()}else if(id==='activity'){setView('activity');loadActivity()}else if(id==='drift'){setView('drift');loadDriftDiffs();loadDriftSummary()}else if(id==='rules'){setView('rules');loadAlertRules()}else if(id==='dashboard'){setView('dashboard');loadExecDash()}else if(id==='settings'){setView('settings');apiFetch('/auth/me').then(d=>{if(d?.id)setUser(d)});loadOrgs();loadIntegrations();loadTags()}else setView(id as string)}

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
  const cancelScan = async(id:number) => { await apiFetch(`/scans/${id}/cancel`,{method:'POST'}); setScanProgress(null); setScanEvents([]); loadScanHistory() }
  const rotateApiKey = () => { setModal({title:'Rotate API Key',msg:'The current key will stop working immediately. Continue?',onConfirm:async()=>{const r=await apiFetch('/auth/rotate-key',{method:'POST'});if(r?.api_key){setUser((u:any)=>({...u,api_key:r.api_key}));setShowApiKey(true);toast('API key rotated','success')}}}) }
  const updateSettings = async() => { if(settingsForm.password&&settingsForm.password!==settingsForm.confirmPassword){setSettingsMsg('Passwords do not match');return} const body:any={}; if(settingsForm.username.trim())body.username=settingsForm.username.trim(); if(settingsForm.password)body.password=settingsForm.password; if(!Object.keys(body).length){setSettingsMsg('No changes to save');return} const r=await apiFetch('/auth/settings',{method:'PUT',body:JSON.stringify(body)}); if(r?.id){setUser(r);setSettingsMsg('Settings updated');setSettingsForm({username:'',password:'',confirmPassword:''})}else{setSettingsMsg(r?.error||'Update failed')} }
  const loadActivity = async(page:number=1) => { setActivityPage(page); const d=await apiFetch(`/activity?page=${page}&per_page=50`); if(d)setActivity(d) }

  // Sprint 4 data loaders
  const loadNotifCount = async () => { const d = await apiFetch('/notifications/unread-count'); if (d) setNotifCount(d.count || 0) }
  const loadNotifications = async () => { const d = await apiFetch('/notifications?per_page=20'); if (d?.items) setNotifications(d.items) }
  const loadOrgs = async () => { const d = await apiFetch('/orgs'); if (Array.isArray(d)) setOrgs(d) }
  const loadComplianceDashboard = async () => { const d = await apiFetch('/compliance/dashboard'); if (d) setComplianceDashboard(d) }
  const loadComplianceFrameworks = async () => { const d = await apiFetch('/compliance/frameworks'); if (Array.isArray(d)) setComplianceFrameworks(d) }
  const loadRemediations = async () => { const d = await apiFetch('/remediations?per_page=50'); if (d?.items) setRemediations(d) }
  const loadRemDashboard = async () => { const d = await apiFetch('/remediations/dashboard'); if (d) setRemDashboard(d) }
  const loadReports = async () => { const d = await apiFetch('/reports?per_page=20'); if (d?.items) setReports(d) }
  const loadReportSchedules = async () => { const d = await apiFetch('/reports/schedules'); if (Array.isArray(d)) setReportSchedules(d) }
  const loadIntegrations = async () => { const d = await apiFetch('/integrations'); if (Array.isArray(d)) setIntegrations(d) }
  // Sprint 5 data loaders
  const loadTags = async()=>{const d=await apiFetch('/tags');if(d?.items)setTags(d.items);else if(Array.isArray(d))setTags(d)}
  const loadBookmarkIds = async()=>{const d=await apiFetch('/bookmarks/ids');if(d?.bucket_ids)setBookmarkIds(d.bucket_ids);else if(Array.isArray(d))setBookmarkIds(d)}
  const loadScanSchedules = async()=>{const d=await apiFetch('/scans/schedules');if(d?.items)setScanSchedules(d.items);else if(Array.isArray(d))setScanSchedules(d)}
  const loadAuditLog = async(p=1)=>{const d=await apiFetch(`/audit-log?page=${p}&per_page=50`);if(d?.items)setAuditLog(d)}
  // Sprint 6 loaders
  const load2faStatus = async()=>{const d=await apiFetch('/auth/2fa/status');if(d)setTwoFaStatus(d)}
  const loadDriftDiffs = async(p=1)=>{const qs=new URLSearchParams({page:String(p),per_page:'50',...(driftFilter.severity?{severity:driftFilter.severity}:{}),...(driftFilter.unreviewed?{unreviewed:'true'}:{})}).toString();const d=await apiFetch(`/drift/diffs?${qs}`);if(d?.items)setDriftDiffs(d)}
  const loadDriftSummary = async()=>{const d=await apiFetch('/drift/diffs/summary');if(d)setDriftSummary(d)}
  const loadAlertRules = async()=>{const d=await apiFetch('/alert-rules');if(d?.items)setAlertRules(d.items)}
  const loadExecDash = async()=>{const [ed,rt,sla]=await Promise.all([apiFetch('/dashboard/executive'),apiFetch('/dashboard/risk-trends?days=30'),apiFetch('/dashboard/remediation-sla')]);if(ed)setExecDash(ed);if(rt)setRiskTrends(rt);if(sla)setRemSla(sla)}

  // ═══════════════════════════════════════════════════════════════
  // ALL VIEWS INLINED — no component functions inside App()
  // This prevents React from remounting inputs on every state change
  // ═══════════════════════════════════════════════════════════════
  return (
    <div style={{minHeight:'100vh',background:'var(--bg-primary)',color:'var(--text-primary)',fontFamily:'var(--font-body)'}}>
      {/* ─── WELCOME MODAL ─── */}
      {showWelcome && user && <div style={{position:'fixed',inset:0,zIndex:200,background:'rgba(0,0,0,0.7)',backdropFilter:'blur(8px)',display:'flex',alignItems:'center',justifyContent:'center'}} onClick={()=>setShowWelcome(false)}>
        <div onClick={e=>e.stopPropagation()} className="card-static fade-in" style={{width:520,padding:40,textAlign:'center',borderRadius:16}}>
          <div style={{width:56,height:56,borderRadius:14,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:28,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900,marginBottom:16}}>☁</div>
          <h2 style={{fontSize:24,fontWeight:700,fontFamily:'var(--font-display)',margin:'0 0 8px'}}>Welcome, <span style={{color:'var(--accent)'}}>{user.username}</span>!</h2>
          <p style={{fontSize:13,color:'var(--text-tertiary)',margin:'0 0 28px'}}>Your BucketAudit account is ready. Here's what you can do:</p>
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
          <button onClick={()=>setShowWelcome(false)} className="btn-primary" style={{width:'100%',borderRadius:10,padding:14,fontSize:14,fontFamily:'var(--font-body)'}}>Get Started</button>
        </div></div>}

      {/* ─── NAV ─── */}
      {navDropdown && <div onClick={()=>setNavDropdown(null)} style={{position:'fixed',inset:0,zIndex:99}}/>}
      <nav style={{position:'fixed',top:0,left:0,right:0,zIndex:100,padding:'0 16px',height:48,display:'flex',alignItems:'center',gap:12,flexWrap:'nowrap'}}>
        <div onClick={()=>setView('home')} style={{cursor:'pointer',display:'flex',alignItems:'center',gap:8,flexShrink:0}}>
          <div style={{width:24,height:24,borderRadius:5,display:'flex',alignItems:'center',justifyContent:'center',fontSize:13,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900}}>☁</div>
          <span style={{fontFamily:'var(--font-display)',fontWeight:700,fontSize:15,color:'var(--text-primary)',letterSpacing:'-0.5px'}}>Bucket<span style={{color:'var(--accent)'}}>Audit</span></span></div>
        {(()=>{
          const NB=({id,l,ic}:{id:string,l:string,ic:string})=><button className="nav-primary-item" onClick={()=>navGo(id)}
            style={{background:view===id?'var(--bg-tertiary)':'transparent',border:view===id?'1px solid var(--border-default)':'1px solid transparent',color:view===id?'var(--accent)':'var(--text-secondary)',padding:'5px 10px',borderRadius:7,cursor:'pointer',fontSize:12,fontWeight:view===id?600:400,fontFamily:'var(--font-body)',transition:'all 0.15s',whiteSpace:'nowrap' as const,flexShrink:0}}>
            <span style={{marginRight:4,fontSize:10}}>{ic}</span>{l}
            {id==='monitor'&&monDash?.unread_alerts?<span style={{background:'var(--danger)',color:'#fff',fontSize:9,padding:'1px 5px',borderRadius:8,marginLeft:4}}>{monDash.unread_alerts}</span>:null}
          </button>
          const moreActive=['drift','compliance','intelligence','ai-insights','pricing'].includes(view)
          return <div className="primary-nav" style={{display:'flex',gap:2,flexWrap:'nowrap',alignItems:'center',position:'relative'}}>
            <NB id="search" l="Files" ic="⌕"/>
            <NB id="buckets" l="Buckets" ic="◫"/>
            <NB id="scan" l="Scanner" ic="⟳"/>
            <NB id="monitor" l="Monitor" ic="◉"/>
            <NB id="dashboard" l="Dashboard" ic="◈"/>
            <button onClick={()=>setNavDropdown(navDropdown==='more'?null:'more')}
              style={{background:moreActive||navDropdown==='more'?'var(--bg-tertiary)':'transparent',border:moreActive||navDropdown==='more'?'1px solid var(--border-default)':'1px solid transparent',color:moreActive?'var(--accent)':'var(--text-secondary)',padding:'5px 10px',borderRadius:7,cursor:'pointer',fontSize:12,fontFamily:'var(--font-body)',whiteSpace:'nowrap' as const}}>
              More <span style={{fontSize:8,marginLeft:3}}>{navDropdown==='more'?'▲':'▼'}</span>
            </button>
            {navDropdown==='more' && <div style={{position:'absolute',top:'calc(100% + 8px)',right:0,minWidth:190,padding:5,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',boxShadow:'var(--shadow-lg)',zIndex:201}}>
              {([['drift','Drift Detection','△'],['compliance','Compliance','☑'],['intelligence','Intelligence','⬡'],['ai-insights','AI Insights','✦'],['pricing','Pricing','◇']]).map(([id,l,ic])=><button key={id} onClick={()=>navGo(id)}
                style={{display:'flex',alignItems:'center',gap:9,width:'100%',padding:'9px 11px',background:view===id?'var(--bg-tertiary)':'transparent',border:'none',borderRadius:7,color:view===id?'var(--accent)':'var(--text-secondary)',fontSize:12,textAlign:'left',fontFamily:'var(--font-body)'}}>
                <span style={{width:16,textAlign:'center'}}>{ic}</span>{l}
              </button>)}
            </div>}
          </div>
        })()}
        <div style={{position:'relative'}}>
          <button className="mobile-nav-trigger" onClick={()=>setNavDropdown(navDropdown==='mobile'?null:'mobile')}>Menu <span>{navDropdown==='mobile'?'▲':'▼'}</span></button>
          {navDropdown==='mobile' && <div className="mobile-nav-menu">
            {([['search','Files','⌕'],['buckets','Buckets','◫'],['scan','Scanner','⟳'],['monitor','Monitor','◉'],['dashboard','Dashboard','◈'],['drift','Drift Detection','△'],['compliance','Compliance','☑'],['intelligence','Intelligence','⬡'],['ai-insights','AI Insights','✦'],['pricing','Pricing','◇']]).map(([id,l,ic])=><button key={id} onClick={()=>navGo(id)} className={view===id?'active':''}><span>{ic}</span>{l}</button>)}
          </div>}
        </div>
        <div style={{flex:1,minWidth:0}}/>
        <div style={{display:'flex',alignItems:'center',gap:8,flexShrink:0}}>
          <button onClick={()=>setTheme(theme==='dark'?'light':'dark')} style={{background:'none',border:'1px solid var(--border-subtle)',borderRadius:5,padding:'3px 7px',cursor:'pointer',fontSize:13,color:'var(--text-secondary)',lineHeight:1}} title={theme==='dark'?'Switch to light mode':'Switch to dark mode'}>{theme==='dark'?'☀':'☾'}</button>
          {sseConnected && <div style={{display:'flex',alignItems:'center',gap:4,fontSize:10,color:'var(--accent)'}}>
            <div style={{width:5,height:5,borderRadius:'50%',background:'var(--accent)',animation:'pulse 2s infinite'}}/>LIVE</div>}
          {user && <div style={{position:'relative',cursor:'pointer'}} onClick={()=>{setShowNotifPanel(!showNotifPanel);if(!showNotifPanel)loadNotifications()}}>
            <span style={{fontSize:16}} title="Notifications">🔔</span>
            {notifCount > 0 && <span style={{position:'absolute',top:-5,right:-5,background:'#f04848',color:'#fff',borderRadius:'50%',width:14,height:14,fontSize:9,display:'flex',alignItems:'center',justifyContent:'center',fontWeight:700}}>{notifCount > 9 ? '9+' : notifCount}</span>}
          </div>}
          {user ? <div style={{position:'relative'}}>
            <button onClick={()=>setNavDropdown(navDropdown==='user'?null:'user')}
              style={{display:'flex',alignItems:'center',gap:6,background:navDropdown==='user'?'var(--bg-hover)':'none',border:'1px solid var(--border-subtle)',borderRadius:7,padding:'4px 10px',cursor:'pointer',transition:'all 0.15s'}}>
              <div style={{width:22,height:22,borderRadius:'50%',background:'linear-gradient(135deg,var(--accent),#00c568)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:10,fontWeight:800,color:'#000'}}>{(user.username||user.email||'U')[0].toUpperCase()}</div>
              <span style={{fontSize:11,color:'var(--text-secondary)',maxWidth:80,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{user.username}</span>
              <span style={{fontSize:8,color:'var(--text-muted)'}}>{navDropdown==='user'?'▲':'▼'}</span>
            </button>
            {navDropdown==='user' && <div style={{position:'absolute',top:'calc(100% + 4px)',right:0,minWidth:200,padding:4,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:'var(--radius-lg)',boxShadow:'var(--shadow-lg)',zIndex:201}}>
              <div style={{padding:'8px 12px',borderBottom:'1px solid var(--border-subtle)',marginBottom:4}}>
                <div style={{fontSize:12,fontWeight:600,color:'var(--text-primary)'}}>{user.username}</div>
                <div style={{fontSize:10,color:'var(--text-muted)'}}>{user.email}</div>
                <div style={{fontSize:9,color:'var(--accent)',fontWeight:700,textTransform:'uppercase' as const,marginTop:2}}>{user.tier||'free'} plan</div>
              </div>
              {([['settings','Settings','⚙'],['rules','Alert Rules','⚑'],['remediate','Remediation','✓'],['api-docs','API Docs','{ }']]).map(([id,l,ic])=>
                <button key={id} onClick={()=>navGo(id)}
                  style={{display:'flex',alignItems:'center',gap:8,width:'100%',padding:'8px 12px',background:view===id?'var(--bg-tertiary)':'transparent',border:'none',borderRadius:6,cursor:'pointer',color:view===id?'var(--accent)':'var(--text-secondary)',fontSize:12,fontWeight:view===id?600:400,fontFamily:'var(--font-body)',textAlign:'left',transition:'background 0.1s'}}>
                  <span style={{fontSize:11,width:16,textAlign:'center'}}>{ic}</span>{l}
                </button>)}
              <div style={{borderTop:'1px solid var(--border-subtle)',marginTop:4,paddingTop:4}}>
                <button onClick={()=>{setNavDropdown(null);doLogout()}}
                  style={{display:'flex',alignItems:'center',gap:8,width:'100%',padding:'8px 12px',background:'transparent',border:'none',borderRadius:6,cursor:'pointer',color:'var(--danger)',fontSize:12,fontFamily:'var(--font-body)',textAlign:'left',transition:'background 0.1s'}}>
                  <span style={{fontSize:11,width:16,textAlign:'center'}}>⏻</span>Logout
                </button>
              </div>
            </div>}
          </div>
          : <button onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('');setView('auth')}} style={{background:'var(--accent)',border:'none',color:'#000',padding:'5px 14px',borderRadius:7,cursor:'pointer',fontSize:11,fontWeight:600}}>Sign In</button>}
        </div>
        {showNotifPanel && <div className="card-static" style={{position:'absolute',top:44,right:60,width:360,maxHeight:400,boxShadow:'var(--shadow-lg)',zIndex:1000,overflow:'auto',padding:8}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 12px',borderBottom:'1px solid var(--border-default)'}}>
            <span style={{fontWeight:700,fontSize:14}}>Notifications</span>
            <button onClick={async()=>{await apiFetch('/notifications/read-all',{method:'POST'});loadNotifCount();loadNotifications()}} style={{background:'none',border:'none',color:'var(--accent)',cursor:'pointer',fontSize:12}}>Mark all read</button>
          </div>
          {notifications.length === 0 ? <div style={{padding:20,textAlign:'center',color:'var(--text-secondary)',fontSize:13}}>No notifications</div> :
          notifications.map((n:any)=><div key={n.id} onClick={async()=>{if(!n.is_read){await apiFetch(`/notifications/${n.id}/read`,{method:'POST'});loadNotifCount();loadNotifications()}}} style={{padding:'10px 12px',borderBottom:'1px solid var(--border-default)',cursor:'pointer',opacity:n.is_read?0.6:1,background:n.is_read?'transparent':'rgba(0,255,136,0.05)'}}>
            <div style={{fontWeight:600,fontSize:13}}>{n.title}</div>
            {n.body && <div style={{fontSize:12,color:'var(--text-secondary)',marginTop:4}}>{n.body}</div>}
            <div style={{fontSize:11,color:'var(--text-secondary)',marginTop:4}}>{new Date(n.created_at).toLocaleString()}</div>
          </div>)}
        </div>}
      </nav>

      {/* ─── AUTH ─── */}
      {view==='auth' && <div style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center'}}>
        <div className="card-static fade-in" style={{width:420,padding:40}}>
          <div style={{textAlign:'center',marginBottom:32}}>
            <div style={{width:48,height:48,borderRadius:12,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:24,background:'linear-gradient(135deg,var(--accent),#00c568)',color:'#000',fontWeight:900,marginBottom:12}}>☁</div>
            <h2 style={{fontSize:24,fontWeight:700,fontFamily:'var(--font-display)',margin:'0 0 4px'}}>Bucket<span style={{color:'var(--accent)'}}>Audit</span></h2>
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

          {/* 2FA verification */}
          {twoFaTempToken && authMode==='login' && <div style={{marginBottom:16}}>
            <label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>2FA CODE</label>
            <input value={twoFaCode} onChange={e=>setTwoFaCode(e.target.value)} placeholder="Enter 6-digit code or backup code" maxLength={8} onKeyDown={e=>e.key==='Enter'&&doVerify2fa()} style={IS}/>
            <button onClick={doVerify2fa} disabled={authLoading||!twoFaCode} style={{width:'100%',marginTop:12,background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Verifying...':'Verify 2FA'}</button>
          </div>}

          {/* Action buttons */}
          {authMode==='login' && !twoFaTempToken && <button onClick={doLogin} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Signing in...':'Sign In'}</button>}
          {authMode==='register' && <button onClick={doRegister} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Creating...':'Create Account'}</button>}
          {authMode==='forgot' && <button onClick={doForgotPassword} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Sending...':'Send Reset Link'}</button>}
          {authMode==='reset' && <button onClick={doResetPassword} disabled={authLoading} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',opacity:authLoading?0.6:1}}>{authLoading?'Resetting...':'Reset Password'}</button>}

          {/* Footer links */}
          {authMode==='login' && <p style={{textAlign:'center',marginTop:16,fontSize:11,color:'var(--text-muted)'}}>No account? <span onClick={()=>{setAuthMode('register');setAuthError('');setAuthSuccess('')}} style={{color:'var(--accent)',cursor:'pointer'}}>Register</span></p>}
          {authMode==='register' && <p style={{textAlign:'center',marginTop:16,fontSize:11,color:'var(--text-muted)'}}>Already have an account? <span onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('')}} style={{color:'var(--accent)',cursor:'pointer'}}>Sign in</span></p>}
          {authMode==='forgot' && <p style={{textAlign:'center',marginTop:16,fontSize:11,color:'var(--text-muted)'}}>Already have a token? <span onClick={()=>{setAuthMode('reset');setAuthError('');setAuthSuccess('')}} style={{color:'var(--accent)',cursor:'pointer'}}>Reset password</span></p>}
        </div></div>}

      {/* ─── HOME ─── */}
      {view==='home' && <main className="home-shell">
        <div className="home-grid"/>
        <section className="home-content home-hero fade-in">
          <div className="home-eyebrow"><span/>EXTERNAL CLOUD STORAGE EXPOSURE MONITORING</div>
          <h1>Know when public cloud storage exposes your data.</h1>
          <p className="home-subtitle">BucketAudit helps security teams discover and monitor publicly reachable object storage across AWS, Azure, GCP, DigitalOcean, and Alibaba Cloud.</p>

          <div className="home-hero-actions">
            <button className="btn-primary" onClick={()=>{if(user){setScanForm({keywords:'',companies:'',providers:[]});setView('scan');loadScanHistory()}else{setAuthMode('register');setAuthError('');setAuthSuccess('');setView('auth')}}}>Check my organization</button>
            <button onClick={()=>loadBk()}>Explore exposed storage <span>→</span></button>
          </div>

          <div className="home-trust-line"><span>Read-only checks</span><span>Public endpoints only</span><span>No cloud credentials required</span><span>Evidence recorded</span></div>

          <div className="home-search-label">SEARCH THE PUBLIC EXPOSURE INDEX</div>
          <div className="home-search slide-up">
            <span aria-hidden="true">⌕</span>
            <input value={heroQ} onChange={e=>setHeroQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSearch(heroQ)} placeholder="Search exposed file metadata by filename, extension, or keyword"/>
            <button onClick={()=>doSearch(heroQ)} className="btn-primary">Search</button>
          </div>

          <div className="home-examples"><span>Try</span>{['.env','backup.sql','credentials.json','*.csv'].map(q=><button key={q} onClick={()=>{setHeroQ(q);doSearch(q)}}>{q}</button>)}</div>

          {user && <div className="home-actions">
            <button className="home-action-primary" onClick={()=>{setScanForm({keywords:'backup, staging, dev, test, config',companies:'example',providers:[]});setView('scan');loadScanHistory()}}><span>⟳</span><div><strong>Start a scan</strong><small>Discover cloud buckets</small></div></button>
            <button className="home-action" onClick={()=>loadMonitor()}><span>◉</span><div><strong>Set up monitoring</strong><small>Watch assets continuously</small></div></button>
          </div>}

          {stats && <div className="home-summary">
            <div><strong>{fnum(stats.total_buckets)}</strong><span>Buckets</span></div>
            <div><strong className="home-open-count">{fnum(stats.open_buckets)}</strong><span>Open</span></div>
            <div><strong>{fnum(stats.total_files)}</strong><span>Files</span></div>
            <div><strong>{fmt(stats.total_size_bytes)}</strong><span>Indexed</span></div>
            <button onClick={()=>navGo('dashboard')}>View dashboard <span>→</span></button>
          </div>}
        </section>

        <section className="home-section" aria-labelledby="home-how-title">
          <div className="home-section-heading">
            <div className="home-section-kicker">HOW IT WORKS</div>
            <h2 id="home-how-title">From a company name to verified exposure evidence.</h2>
            <p>BucketAudit narrows public cloud storage discovery to the organizations and assets that matter to you.</p>
          </div>
          <div className="home-steps">
            {[
              ['01','Define your scope','Enter company, brand, product, domain, or storage keywords and choose the cloud providers to check.'],
              ['02','Discover public exposure','BucketAudit tests likely object-storage endpoints for unauthenticated public access using read-only requests.'],
              ['03','Verify and monitor','Review exposed file metadata and access evidence, then schedule monitoring for status or file changes.'],
            ].map(([number,title,description])=><article className="home-step" key={number}>
              <span>{number}</span><h3>{title}</h3><p>{description}</p>
            </article>)}
          </div>
        </section>

        <section className="home-section home-scope" aria-labelledby="home-detect-title">
          <div>
            <div className="home-section-heading home-section-heading-left">
              <div className="home-section-kicker">WHAT BUCKETAUDIT FINDS</div>
              <h2 id="home-detect-title">The external storage risks hidden outside your inventory.</h2>
            </div>
            <div className="home-detection-grid">
              {[
                ['Public buckets','Object storage endpoints that permit unauthenticated listing or public website access.'],
                ['Sensitive filenames','Backups, credentials, configuration, databases, source code, and operational logs.'],
                ['Exposure changes','New buckets, changed access status, and files added or removed between scans.'],
                ['Organization risk','Potential exposures associated with company, brand, product, or domain identifiers.'],
              ].map(([title,description])=><article key={title}><h3>{title}</h3><p>{description}</p></article>)}
            </div>
          </div>

          <aside className="home-responsible">
            <div className="home-section-kicker">RESPONSIBLE BY DESIGN</div>
            <h2>Evidence without bypassing access controls.</h2>
            <p>Discovery uses read-only requests against publicly reachable storage endpoints. BucketAudit does not bypass authentication, modify cloud resources, or claim ownership without supporting evidence.</p>
            <ul>
              <li><span>✓</span> Public endpoint checks only</li>
              <li><span>✓</span> Reproducible access evidence</li>
              <li><span>✓</span> Verified, inferred, or unverified attribution</li>
              <li><span>✓</span> Monitoring and remediation workflows</li>
            </ul>
          </aside>
        </section>

        <section className="home-final-cta">
          <div><div className="home-section-kicker">START WITH YOUR EXTERNAL FOOTPRINT</div><h2>See what the public internet can already reach.</h2></div>
          <button className="btn-primary" onClick={()=>{if(user){setScanForm({keywords:'',companies:'',providers:[]});setView('scan');loadScanHistory()}else{setAuthMode('register');setAuthError('');setAuthSuccess('');setView('auth')}}}>{user?'Run discovery scan':'Create free account'}</button>
        </section>

        <footer className="home-footer-note">BucketAudit is a defensive security platform for discovering and monitoring publicly accessible cloud storage. Use it only for authorized security and research purposes.</footer>
      </main>}

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
        {/* Advanced Filters */}
        <div style={{marginBottom:12}}>
          <button onClick={()=>setShowAdvFilters(!showAdvFilters)} style={{background:showAdvFilters?'var(--bg-tertiary)':'var(--bg-secondary)',border:`1px solid ${showAdvFilters?'var(--accent)':'var(--border-subtle)'}`,borderRadius:8,padding:'5px 14px',cursor:'pointer',color:showAdvFilters?'var(--accent)':'var(--text-muted)',fontSize:11,fontWeight:600}}>⚙ Advanced Filters {showAdvFilters?'▾':'▸'}</button>
          {showAdvFilters && <div style={{marginTop:8,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:10,padding:16}}>
            <div style={{display:'flex',gap:12,flexWrap:'wrap',alignItems:'end'}}>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>DATE FROM</label><input type="date" value={advFilters.date_from} onChange={e=>setAdvFilters({...advFilters,date_from:e.target.value})} style={{...IS,padding:'6px 10px',fontSize:11,width:140}}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>DATE TO</label><input type="date" value={advFilters.date_to} onChange={e=>setAdvFilters({...advFilters,date_to:e.target.value})} style={{...IS,padding:'6px 10px',fontSize:11,width:140}}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>MIN SIZE (KB)</label><input type="number" value={advFilters.min_size} onChange={e=>setAdvFilters({...advFilters,min_size:e.target.value})} placeholder="0" style={{...IS,padding:'6px 10px',fontSize:11,width:100}}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>MAX SIZE (MB)</label><input type="number" value={advFilters.max_size} onChange={e=>setAdvFilters({...advFilters,max_size:e.target.value})} placeholder="100" style={{...IS,padding:'6px 10px',fontSize:11,width:100}}/></div>
              <button onClick={()=>{if(sq)doSearch(sq)}} style={{background:'var(--accent)',border:'none',borderRadius:6,padding:'7px 14px',color:'#000',fontSize:11,fontWeight:700,cursor:'pointer'}}>Apply</button>
              <button onClick={()=>{setAdvFilters({date_from:'',date_to:'',min_size:'',max_size:''});if(sq)doSearch(sq,sf,regexMode,{date_from:'',date_to:'',min_size:'',max_size:''})}} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'7px 14px',color:'var(--text-muted)',fontSize:11,cursor:'pointer'}}>Clear</button>
            </div>
          </div>}
          {(advFilters.date_from||advFilters.date_to||advFilters.min_size||advFilters.max_size) && <div style={{display:'flex',gap:6,marginTop:8,flexWrap:'wrap'}}>
            {advFilters.date_from && <span style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'2px 8px',borderRadius:12,fontSize:10,display:'flex',alignItems:'center',gap:4}}>From: {advFilters.date_from} <span onClick={()=>{setAdvFilters(f=>({...f,date_from:''}));if(sq)doSearch(sq,sf,regexMode,{...advFilters,date_from:''})}} style={{cursor:'pointer',fontSize:12}}>✕</span></span>}
            {advFilters.date_to && <span style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'2px 8px',borderRadius:12,fontSize:10,display:'flex',alignItems:'center',gap:4}}>To: {advFilters.date_to} <span onClick={()=>{setAdvFilters(f=>({...f,date_to:''}));if(sq)doSearch(sq,sf,regexMode,{...advFilters,date_to:''})}} style={{cursor:'pointer',fontSize:12}}>✕</span></span>}
            {advFilters.min_size && <span style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'2px 8px',borderRadius:12,fontSize:10,display:'flex',alignItems:'center',gap:4}}>Min: {advFilters.min_size}KB <span onClick={()=>{setAdvFilters(f=>({...f,min_size:''}));if(sq)doSearch(sq,sf,regexMode,{...advFilters,min_size:''})}} style={{cursor:'pointer',fontSize:12}}>✕</span></span>}
            {advFilters.max_size && <span style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'2px 8px',borderRadius:12,fontSize:10,display:'flex',alignItems:'center',gap:4}}>Max: {advFilters.max_size}MB <span onClick={()=>{setAdvFilters(f=>({...f,max_size:''}));if(sq)doSearch(sq,sf,regexMode,{...advFilters,max_size:''})}} style={{cursor:'pointer',fontSize:12}}>✕</span></span>}
          </div>}
        </div>
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
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16,flexWrap:'wrap',gap:12}}>
          <h2 style={{fontSize:20,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>Public Buckets <span style={{fontSize:13,color:'var(--text-muted)',marginLeft:12}}>{fnum(buckets?.total||0)} indexed</span></h2></div>
        <div className="card-static" style={{padding:16,marginBottom:20,display:'flex',gap:12,alignItems:'center',flexWrap:'wrap'}}>
          <div style={{flex:1,minWidth:200,display:'flex',alignItems:'center',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,overflow:'hidden'}}>
            <span style={{padding:'0 12px',color:'var(--text-muted)',fontSize:14}}>⌕</span>
            <input value={bucketSearch} onChange={e=>setBucketSearch(e.target.value)} onKeyDown={e=>{if(e.key==='Enter')loadBk({page:1})}} placeholder="Search by bucket name..." style={{flex:1,background:'none',border:'none',color:'var(--text-primary)',fontSize:13,padding:'10px 12px 10px 0',fontFamily:'var(--font-body)'}}/>
            {bucketSearch && <button onClick={()=>{setBucketSearch('');setTimeout(()=>loadBk({page:1,search:''}),0)}} style={{background:'none',border:'none',color:'var(--text-muted)',cursor:'pointer',padding:'0 10px',fontSize:14}}>✕</button>}
          </div>
          <select value={bucketStatusFilter} onChange={e=>{setBucketStatusFilter(e.target.value);loadBk({page:1,status:e.target.value||undefined})}} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'9px 12px',color:'var(--text-secondary)',fontSize:12,fontFamily:'var(--font-body)',cursor:'pointer',minWidth:110}}>
            <option value="">All Status</option><option value="open">Open</option><option value="closed">Closed</option><option value="partial">Partial</option>
          </select>
          <div style={{display:'flex',gap:4}}>{['all','aws','azure','gcp','digitalocean','alibaba'].map(p=><button key={p} onClick={()=>{const v=p==='all'?'':p;setBucketProviderFilter(v);loadBk({page:1,provider:v||undefined})}} style={{background:bucketProviderFilter===(p==='all'?'':p)?'var(--accent-bg)':'var(--bg-primary)',border:`1px solid ${bucketProviderFilter===(p==='all'?'':p)?'var(--accent)':'var(--border-subtle)'}`,borderRadius:6,padding:'5px 10px',color:bucketProviderFilter===(p==='all'?'':p)?'var(--accent)':'var(--text-tertiary)',fontSize:11,cursor:'pointer',fontWeight:bucketProviderFilter===(p==='all'?'':p)?600:400}}>{p==='all'?'All':PL[p]}</button>)}</div>
          <button onClick={()=>loadBk({page:1})} className="btn-primary" style={{padding:'9px 20px',fontSize:12,fontFamily:'var(--font-body)',borderRadius:8}}>Search</button>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'28px 1fr 95px 85px 75px 90px 85px 85px 75px',gap:12,padding:'8px 16px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'1px',borderBottom:'1px solid var(--border-subtle)'}}><span>★</span><span>Bucket</span><span>Provider</span><span>Region</span><span>Status</span><span>Risk</span><span>Files</span><span>Size</span><span>Scanned</span></div>
        {buckets?.items?.map((b:any,i:number)=><div key={b.id} onClick={()=>loadBd(b.id)} style={{display:'grid',gridTemplateColumns:'28px 1fr 95px 85px 75px 90px 85px 85px 75px',gap:12,padding:'12px 16px',alignItems:'center',cursor:'pointer',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4}}>
          <span onClick={e=>{e.stopPropagation();apiFetch('/bookmarks',{method:'POST',body:JSON.stringify({bucket_id:b.id})}).then(()=>loadBookmarkIds())}} style={{fontSize:16,cursor:'pointer',color:bookmarkIds.includes(b.id)?'var(--accent)':'var(--text-muted)',transition:'color 0.2s'}} title={bookmarkIds.includes(b.id)?'Remove bookmark':'Bookmark'}>{bookmarkIds.includes(b.id)?'★':'☆'}</span>
          <div style={{minWidth:0}}><span style={{fontSize:13,color:'var(--accent-dim)',fontWeight:600}}>{b.name}</span>{b.tags?.length>0&&<span style={{marginLeft:6}}>{b.tags.map((t:any)=><span key={t.id||t.name} style={{background:t.color+'20',color:t.color,border:`1px solid ${t.color}40`,padding:'1px 6px',borderRadius:10,fontSize:9,fontWeight:600,marginLeft:4}}>{t.name}</span>)}</span>}{showTagPicker===b.id&&<div onClick={e=>e.stopPropagation()} style={{position:'absolute',zIndex:50,background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:8,padding:8,boxShadow:'0 4px 16px rgba(0,0,0,0.3)',marginTop:4}}>{tags.map(t=><span key={t.id} onClick={()=>{apiFetch(`/buckets/${b.id}/tags`,{method:'POST',body:JSON.stringify({tag_id:t.id})}).then(()=>{loadBk();setShowTagPicker(null)})}} style={{display:'inline-block',background:t.color+'20',color:t.color,border:`1px solid ${t.color}40`,padding:'2px 8px',borderRadius:10,fontSize:10,fontWeight:600,margin:2,cursor:'pointer'}}>{t.name}</span>)}{tags.length===0&&<span style={{fontSize:10,color:'var(--text-muted)'}}>No tags. Create in Settings.</span>}</div>}<button onClick={e=>{e.stopPropagation();setShowTagPicker(showTagPicker===b.id?null:b.id)}} style={{background:'none',border:'none',color:'var(--text-muted)',cursor:'pointer',fontSize:10,marginLeft:4,padding:0}}>🏷</button><Attribution bucket={b}/><ExposureBadge type={b.exposure_type}/></div>
          <Badge provider={b.provider_name}/><span style={{fontSize:12,color:'var(--text-muted)'}}>{b.region||'—'}</span><SBadge s={b.status}/>{b.risk_score!=null?<RiskBadge score={b.risk_score} level={b.risk_level||'info'}/>:<span style={{fontSize:10,color:'var(--text-muted)'}}>—</span>}<span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fnum(b.file_count)}</span><span style={{fontSize:12,color:'var(--text-tertiary)'}}>{fmt(b.total_size_bytes)}</span><span style={{fontSize:11,color:'var(--text-muted)'}}>{ago(b.last_scanned)}</span></div>)}
        {buckets && buckets.total > (buckets.per_page||50) && (()=>{ const tp=Math.ceil(buckets.total/(buckets.per_page||50)),cp=buckets.page||1; const pages:number[]=[]; if(tp<=7){for(let i=1;i<=tp;i++)pages.push(i)}else{pages.push(1);if(cp>3)pages.push(-1);for(let i=Math.max(2,cp-1);i<=Math.min(tp-1,cp+1);i++)pages.push(i);if(cp<tp-2)pages.push(-1);pages.push(tp)} return <div style={{display:'flex',justifyContent:'center',alignItems:'center',gap:6,marginTop:16}}>
          <button onClick={()=>loadBk({page:cp-1})} disabled={cp===1} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'5px 12px',color:cp===1?'var(--text-muted)':'var(--text-secondary)',fontSize:11,cursor:cp===1?'default':'pointer'}}>Prev</button>
          {pages.map((p,i)=>p===-1?<span key={'e'+i} style={{color:'var(--text-muted)',fontSize:11}}>...</span>:<button key={p} onClick={()=>loadBk({page:p})} style={{background:p===cp?'var(--accent)':'var(--bg-secondary)',border:`1px solid ${p===cp?'var(--accent)':'var(--border-subtle)'}`,borderRadius:6,padding:'5px 10px',color:p===cp?'#000':'var(--text-secondary)',fontSize:11,fontWeight:p===cp?700:400,cursor:'pointer',minWidth:32}}>{p}</button>)}
          <button onClick={()=>loadBk({page:cp+1})} disabled={cp===tp} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:6,padding:'5px 12px',color:cp===tp?'var(--text-muted)':'var(--text-secondary)',fontSize:11,cursor:cp===tp?'default':'pointer'}}>Next</button>
          <span style={{fontSize:10,color:'var(--text-muted)',marginLeft:8}}>Page {cp} of {tp}</span></div> })()}
      </div>}

      {/* ─── BUCKET DETAIL ─── */}
      {view==='bucket-detail' && (bd ? <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <button onClick={()=>setView('buckets')} style={{background:'none',border:'none',color:'var(--text-tertiary)',cursor:'pointer',fontSize:12,marginBottom:16,padding:0}}>← Back</button>
        <div style={{padding:24,marginBottom:24}} className="card-static">
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:16,flexWrap:'wrap'}}><h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>{bd.name}</h2><Badge provider={bd.provider_name} big/><SBadge s={bd.status}/>{bd.risk_score!=null&&<RiskBadge score={bd.risk_score} level={bd.risk_level||'info'}/>}
            {aiAvail&&<button onClick={()=>doClassifyBucket(bd.id)} disabled={classifyLoading} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'5px 14px',borderRadius:6,cursor:'pointer',color:'#fff',fontSize:11,fontWeight:600,opacity:classifyLoading?0.5:1}}>{classifyLoading?'Analyzing...':'✦ AI Analyze'}</button>}
            <button onClick={()=>apiFetch(`/sensitive/scan/${bd.id}`,{method:'POST'}).then(d=>{if(d?.count)toast(`Found ${d.count} sensitive files`,'info');else toast('No sensitive files found','success')})} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',padding:'5px 14px',borderRadius:6,cursor:'pointer',color:'var(--warning)',fontSize:11,fontWeight:600}}>🔍 Scan Sensitive</button>
            <button onClick={()=>apiFetch(`/takedown/${bd.id}`).then(d=>d&&setTakedownGuide(d))} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',padding:'5px 14px',borderRadius:6,cursor:'pointer',color:'#f04848',fontSize:11,fontWeight:600}}>⚠ Takedown Guide</button>
          </div>
          {aiClassSummary && Object.keys(aiClassSummary).length>0 && <div style={{display:'flex',gap:8,marginBottom:16,flexWrap:'wrap'}}>{Object.entries(aiClassSummary).map(([cat,cnt]:any)=><div key={cat} style={{display:'flex',alignItems:'center',gap:4}}><ClassBadge c={cat}/><span style={{fontSize:11,color:'var(--text-muted)'}}>{cnt}</span></div>)}</div>}
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:16}}>{[['Company',bd.company_name],['Ownership',bd.ownership_status],['Attribution',bd.attribution_source],['Confidence',bd.attribution_confidence!=null?`${Math.round(bd.attribution_confidence*100)}%`:'—'],['Exposure type',bd.exposure_type],['Evidence signal',bd.exposure_evidence?.signal],['Evidence confidence',bd.exposure_evidence?.confidence!=null?`${Math.round(bd.exposure_evidence.confidence*100)}%`:'—'],['URL',bd.url],['Region',bd.region||'Global'],['Files',fnum(bd.file_count)],['Size',fmt(bd.total_size_bytes)],['First Seen',bd.first_seen?.split('T')[0]],['Last Scanned',ago(bd.last_scanned)]].map(([l,v]:any)=><div key={l}><div style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase' as const,marginBottom:4}}>{l}</div><div style={{fontSize:13,color:l==='Company'&&v?'var(--info)':'var(--text-secondary)',fontWeight:l==='Company'&&v?600:400,wordBreak:'break-all' as const}}>{v||'—'}</div>{l==='Company'&&v&&bd.ownership_status!=='verified'&&<div style={{fontSize:9,color:'var(--text-muted)',fontStyle:'italic',marginTop:2}}>Inferred association, not verified ownership</div>}</div>)}</div></div>
        {takedownGuide && <div className="card-static" style={{padding:20,marginBottom:24,border:'1px solid #f04848'}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
            <h3 style={{fontSize:14,fontWeight:700,color:'#f04848',margin:0}}>⚠ Takedown / Responsible Disclosure Guide</h3>
            <button onClick={()=>setTakedownGuide(null)} style={{background:'none',border:'none',color:'var(--text-muted)',cursor:'pointer',fontSize:14}}>✕</button></div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:16}}>
            <div><div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4}}>PROVIDER</div><div style={{fontSize:13,fontWeight:600}}>{takedownGuide.provider_display}</div></div>
            <div><div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4}}>ABUSE EMAIL</div><div style={{fontSize:13,color:'var(--info)'}}>{takedownGuide.abuse_email}</div></div></div>
          <div style={{marginBottom:16}}>
            <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:6}}>STEPS</div>
            {takedownGuide.steps?.map((s:string,i:number)=><div key={i} style={{display:'flex',gap:8,padding:'4px 0',fontSize:12,color:'var(--text-secondary)'}}>
              <span style={{color:'var(--accent)',fontWeight:700}}>{i+1}.</span>{s}</div>)}</div>
          <details style={{marginTop:8}}><summary style={{fontSize:11,color:'var(--accent)',cursor:'pointer',fontWeight:600}}>View Email Template</summary>
            <pre style={{marginTop:8,background:'var(--bg-primary)',padding:12,borderRadius:8,fontSize:11,whiteSpace:'pre-wrap',color:'var(--text-secondary)',maxHeight:300,overflow:'auto'}}>{takedownGuide.email_template}</pre></details>
          <div style={{fontSize:10,color:'var(--text-muted)',fontStyle:'italic',marginTop:12}}>{takedownGuide.disclaimer}</div>
        </div>}
        <h3 style={{fontSize:14,color:'var(--text-tertiary)',marginBottom:12}}>Contents ({fnum(bd.files?.total||0)} files)</h3>
        {bd.files?.items?.map((f:any,i:number)=><div key={f.id||i} style={{display:'grid',gridTemplateColumns:'28px 1fr 80px 85px 75px',gap:12,padding:'8px 12px',alignItems:'center',background:i%2===0?'var(--bg-secondary)':'transparent',borderRadius:4}}>
          <span style={{fontSize:16}}>{EI[f.extension]||'📄'}</span><a href={f.url} target="_blank" rel="noopener noreferrer" style={{fontSize:12,color:'var(--accent-dim)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{f.filepath}</a>{f.ai_classification?<ClassBadge c={f.ai_classification}/>:<span style={{fontSize:10,color:'var(--text-muted)'}}>—</span>}<span style={{fontSize:11,color:'var(--text-muted)'}}>{fmt(f.size_bytes)}</span><span style={{fontSize:10,color:'var(--text-muted)'}}>{ago(f.last_modified)}</span></div>)}
      </div> : <Spin/>)}

      {/* ─── SCANNER ─── */}
      {view==='scan' && <div style={{padding:'80px 24px 24px',maxWidth:800,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Bucket Discovery Scanner</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24}}>Real-time scanning across all major cloud providers.</p>
        <LiveScanPanel progress={scanProgress} events={scanEvents}/>
        <div style={{padding:28}} className="card-static">
          <div style={{marginBottom:20}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>KEYWORDS (comma-separated)</label>
            <input value={scanForm.keywords} onChange={e=>setScanForm({...scanForm,keywords:e.target.value})} placeholder="backup, database, config, secret" style={IS}/></div>
          <div style={{marginBottom:20}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:6}}>TARGET COMPANIES (comma-separated)</label>
            <div style={{display:'flex',gap:8}}><input value={scanForm.companies} onChange={e=>setScanForm({...scanForm,companies:e.target.value})} placeholder="acme-corp, globex, initech" style={{...IS,flex:1}}/>
            {aiAvail&&<button onClick={doSuggestKw} disabled={suggestLoading||!scanForm.companies.trim()} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'10px 16px',borderRadius:8,cursor:suggestLoading||!scanForm.companies.trim()?'not-allowed':'pointer',color:'#fff',fontSize:11,fontWeight:600,whiteSpace:'nowrap' as const,opacity:suggestLoading||!scanForm.companies.trim()?0.5:1}}>{suggestLoading?'...':'✦ Suggest'}</button>}</div>
            {suggestedKw.length>0&&<div style={{marginTop:8,display:'flex',gap:4,flexWrap:'wrap'}}>{suggestedKw.map((kw:string)=><span key={kw} style={{background:'#a855f710',border:'1px solid #a855f730',color:'#a855f7',padding:'2px 8px',borderRadius:4,fontSize:10}}>{kw}</span>)}</div>}</div>
          <div style={{marginBottom:24}}><label style={{fontSize:11,color:'var(--text-tertiary)',display:'block',marginBottom:8}}>PROVIDERS</label>
            <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>{Object.entries(PL).map(([k,l])=>{const a=scanForm.providers.includes(k);return <button key={k} onClick={()=>setScanForm({...scanForm,providers:a?scanForm.providers.filter(p=>p!==k):[...scanForm.providers,k]})} style={{background:a?PC[k].bg+'20':'var(--bg-primary)',border:`1px solid ${a?PC[k].bg:'var(--border-subtle)'}`,borderRadius:8,padding:'6px 14px',cursor:'pointer',color:a?PC[k].bg:'var(--text-muted)',fontSize:12,fontWeight:a?600:400}}>{l as string}</button>})}</div></div>
          {scanProgress?.phase==='scanning'?<button onClick={()=>{if(scanStatus?.id)cancelScan(scanStatus.id)}} style={{width:'100%',background:'linear-gradient(135deg,#f04848,#d43030)',border:'none',borderRadius:8,padding:14,color:'#fff',fontWeight:700,fontSize:14,cursor:'pointer',fontFamily:'var(--font-mono)'}}>✕ CANCEL SCAN</button>:<button onClick={startScan} style={{width:'100%',background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:14,color:'#000',fontWeight:700,fontSize:14,cursor:'pointer',fontFamily:'var(--font-mono)'}}>⟳ START DISCOVERY SCAN</button>}
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

        {/* Scan Schedules */}
        <div style={{marginTop:32}}>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:16}}>
            <span style={{fontSize:20}}>&#128337;</span>
            <h3 style={{fontSize:17,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>Scheduled Scans</h3>
            <span style={{fontSize:11,color:'var(--text-muted)',marginLeft:'auto'}}>Auto-runs on schedule across the open internet</span>
          </div>
          <div style={{padding:28,marginBottom:20,borderLeft:'3px solid var(--accent)'}} className="card-static">
            <div style={{fontSize:13,fontWeight:600,marginBottom:16,color:'var(--text-primary)'}}>Create New Schedule</div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4,letterSpacing:'0.5px'}}>SCHEDULE NAME</label><input value={schedForm.name} onChange={e=>setSchedForm({...schedForm,name:e.target.value})} placeholder="e.g. Daily backup scan" style={IS}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4,letterSpacing:'0.5px'}}>FREQUENCY</label><select value={schedForm.frequency} onChange={e=>setSchedForm({...schedForm,frequency:e.target.value})} style={{...IS,appearance:'auto' as any}}><option value="hourly">Every Hour</option><option value="daily">Every Day</option><option value="weekly">Every Week</option><option value="monthly">Every Month</option></select></div>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4,letterSpacing:'0.5px'}}>KEYWORDS (comma-separated)</label><textarea value={schedForm.keywords} onChange={e=>setSchedForm({...schedForm,keywords:e.target.value})} placeholder="backup, database, config, staging" style={{...IS,minHeight:56,resize:'vertical' as const}}/></div>
              <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4,letterSpacing:'0.5px'}}>COMPANIES (optional)</label><textarea value={schedForm.companies} onChange={e=>setSchedForm({...schedForm,companies:e.target.value})} placeholder="acme-corp, globex" style={{...IS,minHeight:56,resize:'vertical' as const}}/></div>
            </div>
            <div style={{marginBottom:16}}>
              <label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:6,letterSpacing:'0.5px'}}>CLOUD PROVIDERS</label>
              <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>{Object.entries(PL).map(([k,l])=>{const active=schedForm.providers.includes(k);return <button key={k} onClick={()=>setSchedForm({...schedForm,providers:active?schedForm.providers.filter(p=>p!==k):[...schedForm.providers,k]})} style={{background:active?PC[k].bg+'20':'var(--bg-primary)',border:`1px solid ${active?PC[k].bg:'var(--border-subtle)'}`,borderRadius:8,padding:'5px 12px',cursor:'pointer',color:active?PC[k].bg:'var(--text-muted)',fontSize:11,fontWeight:active?600:400,transition:'all 0.15s ease'}}>{l as string}</button>})}
                <span style={{fontSize:10,color:'var(--text-tertiary)',alignSelf:'center',marginLeft:4}}>{schedForm.providers.length===0?'All providers':''+schedForm.providers.length+' selected'}</span>
              </div>
            </div>
            <button onClick={async()=>{if(!schedForm.name||!schedForm.keywords.trim())return;await apiFetch('/scans/schedules',{method:'POST',body:JSON.stringify({name:schedForm.name,keywords:schedForm.keywords.split(',').map(s=>s.trim()).filter(Boolean),companies:schedForm.companies?schedForm.companies.split(',').map(s=>s.trim()).filter(Boolean):[],providers:schedForm.providers.length>0?schedForm.providers:[],frequency:schedForm.frequency})});setSchedForm({name:'',keywords:'',companies:'',frequency:'daily',providers:[]});loadScanSchedules()}} className="btn-primary" style={{padding:'10px 28px',fontSize:12,letterSpacing:'0.3px'}}>+ Create Schedule</button>
          </div>

          {scanSchedules.length>0 && <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {scanSchedules.map((s:any)=>{const fc:any={hourly:'#4a9eff',daily:'var(--accent)',weekly:'#f5a623',monthly:'#a855f7'};const kws=(()=>{try{return typeof s.keywords==='string'?JSON.parse(s.keywords):s.keywords||[]}catch{return []}})();const provs=(()=>{try{return typeof s.providers==='string'?JSON.parse(s.providers):s.providers||[]}catch{return []}})();return <div key={s.id} className="card" style={{padding:'16px 20px',display:'flex',justifyContent:'space-between',alignItems:'center',gap:16}}>
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6,flexWrap:'wrap'}}>
                  <span style={{width:8,height:8,borderRadius:'50%',background:s.is_active?'var(--accent)':'var(--text-muted)',flexShrink:0}}/>
                  <span style={{fontSize:14,fontWeight:600}}>{s.name}</span>
                  <span style={{background:(fc[s.frequency]||'var(--text-muted)')+'18',color:fc[s.frequency]||'var(--text-muted)',border:`1px solid ${(fc[s.frequency]||'var(--text-muted)')}40`,padding:'2px 8px',borderRadius:4,fontSize:9,fontWeight:700,textTransform:'uppercase' as const}}>{s.frequency}</span>
                  {provs.length>0 && provs.map((p:string)=><span key={p} style={{background:(PC[p]?.bg||'#666')+'18',color:PC[p]?.bg||'#666',padding:'1px 6px',borderRadius:4,fontSize:9,fontWeight:600}}>{p.toUpperCase()}</span>)}
                </div>
                <div style={{display:'flex',gap:12,fontSize:11,color:'var(--text-muted)',flexWrap:'wrap'}}>
                  <span title="Keywords">&#128269; {kws.join(', ')||'—'}</span>
                  <span title="Last run">&#9203; Last: {s.last_run_at?ago(s.last_run_at):'Never'}</span>
                  <span title="Next run">&#9654; Next: {s.next_run_at?new Date(s.next_run_at).toLocaleString():'—'}</span>
                  {s.last_job_id && <span style={{color:'var(--text-tertiary)'}}>Job #{s.last_job_id}</span>}
                </div>
              </div>
              <div style={{display:'flex',gap:6,flexShrink:0}}>
                <button onClick={()=>apiFetch(`/scans/schedules/${s.id}/toggle`,{method:'POST'}).then(()=>loadScanSchedules())} style={{background:s.is_active?'var(--warning)'+'12':'var(--accent-bg)',border:`1px solid ${s.is_active?'var(--warning)'+'40':'rgba(0,232,123,0.2)'}`,color:s.is_active?'var(--warning)':'var(--accent)',padding:'5px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>{s.is_active?'Pause':'Enable'}</button>
                <button onClick={()=>apiFetch(`/scans/schedules/${s.id}/run`,{method:'POST'}).then(()=>{loadScanSchedules();loadScanHistory()})} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'5px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Run Now</button>
                <button onClick={()=>{if(confirm('Delete this schedule?'))apiFetch(`/scans/schedules/${s.id}`,{method:'DELETE'}).then(()=>loadScanSchedules())}} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'5px 12px',borderRadius:6,cursor:'pointer',fontSize:10}}>Delete</button>
              </div>
            </div>})}
          </div>}
          {scanSchedules.length===0 && <div style={{textAlign:'center',padding:40,color:'var(--text-muted)',fontSize:12}} className="card-static">
            <div style={{fontSize:32,marginBottom:8,opacity:0.4}}>&#128337;</div>
            No scan schedules configured yet. Create one above to automatically scan the open internet for your keywords on a recurring basis.
          </div>}
        </div>
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
          <div style={{padding:24,marginBottom:24}} className="card-static">
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
            {watchlists.map((wl:any)=><div key={wl.id} style={{padding:20,marginBottom:8,display:'flex',justifyContent:'space-between',alignItems:'center'}} className="card">
              <div><div style={{fontSize:14,fontWeight:600,marginBottom:4}}>{wl.name}</div><div style={{fontSize:11,color:'var(--text-muted)'}}>Keywords: {(typeof wl.keywords==='string'?JSON.parse(wl.keywords):wl.keywords).join(', ')} | Every {wl.scan_interval_hours}h | Last: {ago(wl.last_scan_at)}</div></div>
              <div style={{display:'flex',gap:6}}><button onClick={()=>triggerWlScan(wl.id)} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'5px 12px',borderRadius:8,cursor:'pointer',fontSize:11}}>Scan Now</button><button onClick={()=>deleteWl(wl.id)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'5px 12px',borderRadius:8,cursor:'pointer',fontSize:11}}>Delete</button></div></div>)}</div>}
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:12,flexWrap:'wrap'}}>
            <h3 style={{fontSize:15,margin:0}}>Alerts {alerts?.total?<span style={{fontSize:12,color:'var(--text-muted)'}}>({alerts.total})</span>:null}</h3>
            {monDash?.unread_alerts>0&&<button onClick={markAllAlertsRead} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Mark All Read</button>}
            {aiAvail&&alerts?.items?.length>0&&<button onClick={doPrioritizeAlerts} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'4px 12px',borderRadius:6,cursor:'pointer',color:'#fff',fontSize:10,fontWeight:600}}>✦ AI Prioritize</button>}
            <div style={{display:'flex',gap:4,marginLeft:'auto'}}>{['','critical','high','medium','low','info'].map(s=><button key={s} onClick={()=>{setAlertSevFilter(s);const params=s?`?severity=${s}`:'';apiFetch(`/monitor/alerts${params}`).then(d=>{if(d)setAlerts(d)})}} style={{background:alertSevFilter===s?'var(--bg-tertiary)':'transparent',border:alertSevFilter===s?'1px solid var(--border-default)':'1px solid transparent',color:alertSevFilter===s?'var(--accent)':'var(--text-muted)',padding:'3px 10px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,textTransform:'uppercase' as const}}>{s||'All'}</button>)}</div>
          </div>
          {!alerts?.items?.length ? <div style={{textAlign:'center',padding:40,color:'var(--text-muted)',fontSize:13}}>No alerts yet. Create a watchlist and run a scan.</div>
          : <div style={{display:'flex',flexDirection:'column',gap:4}}>
            {bulkAlerts.length>0 && <div style={{display:'flex',alignItems:'center',gap:10,padding:'8px 16px',background:'var(--bg-tertiary)',border:'1px solid var(--accent)',borderRadius:8,marginBottom:4}}>
              <span style={{fontSize:12,fontWeight:700,color:'var(--accent)'}}>{bulkAlerts.length} selected</span>
              <button onClick={async()=>{await apiFetch('/monitor/alerts/bulk-read',{method:'POST',body:JSON.stringify({alert_ids:bulkAlerts})});setBulkAlerts([]);loadMonitor()}} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Mark Read</button>
              <button onClick={async()=>{await apiFetch('/monitor/alerts/bulk-resolve',{method:'POST',body:JSON.stringify({alert_ids:bulkAlerts})});setBulkAlerts([]);loadMonitor()}} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Resolve All</button>
              <button onClick={()=>setBulkAlerts([])} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10}}>Clear</button>
            </div>}
            {alerts.items.map((a:any)=><div key={a.id} onClick={()=>!a.is_read&&markAlertRead(a.id)} style={{background:a.is_resolved?'var(--bg-primary)':a.is_read?'var(--bg-secondary)':'var(--bg-tertiary)',border:`1px solid ${a.is_resolved?'var(--border-subtle)':a.is_read?'var(--border-default)':'var(--border-strong)'}`,borderRadius:8,padding:'12px 16px',display:'flex',alignItems:'center',gap:12,cursor:'pointer',opacity:a.is_resolved?0.6:1}}>
            <input type="checkbox" checked={bulkAlerts.includes(a.id)} onChange={e=>{e.stopPropagation();setBulkAlerts(prev=>prev.includes(a.id)?prev.filter(x=>x!==a.id):[...prev,a.id])}} onClick={e=>e.stopPropagation()} style={{width:14,height:14,accentColor:'var(--accent)',cursor:'pointer',flexShrink:0}}/>
            <SevBadge s={a.severity}/><div style={{flex:1,minWidth:0}}><div style={{fontSize:13,fontWeight:a.is_read?400:600,whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis',textDecoration:a.is_resolved?'line-through':'none'}}>{a.title}</div><div style={{fontSize:11,color:'var(--text-muted)',whiteSpace:'nowrap' as const,overflow:'hidden',textOverflow:'ellipsis'}}>{a.description}</div></div>
            {a.is_resolved?<span style={{fontSize:10,color:'var(--accent)',fontWeight:600}}>✓ Resolved</span>:<button onClick={(e)=>{e.stopPropagation();resolveAlert(a.id)}} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'3px 8px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>Resolve</button>}
            <button onClick={async(e)=>{e.stopPropagation();await apiFetch(`/alerts/${a.id}/remediate`,{method:'POST',body:JSON.stringify({title:a.title,priority:a.severity})})}} style={{background:'rgba(0,255,136,0.08)',border:'1px solid rgba(0,232,123,0.25)',color:'var(--accent)',padding:'3px 8px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>✓ Fix</button>
            <button onClick={async(e)=>{e.stopPropagation();const r=await apiFetch(`/alerts/${a.id}/create-jira`,{method:'POST'});toast(r?.success?'Jira issue: '+r.issue_key:'No Jira integration configured',r?.success?'success':'error')}} style={{background:'rgba(0,100,255,0.08)',border:'1px solid rgba(74,158,255,0.25)',color:'#4a9eff',padding:'3px 8px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>⬆ Jira</button>
            {a.ai_priority_score!=null&&<span style={{background:'#a855f715',border:'1px solid #a855f730',color:'#a855f7',padding:'1px 6px',borderRadius:4,fontSize:10,fontWeight:600,whiteSpace:'nowrap' as const}}>⚡{a.ai_priority_score}</span>}{a.provider_name&&<Badge provider={a.provider_name}/>}<span style={{fontSize:10,color:'var(--text-muted)',whiteSpace:'nowrap' as const}}>{ago(a.created_at)}</span>{!a.is_read&&<div style={{width:8,height:8,borderRadius:'50%',background:'var(--accent)',flexShrink:0}}/>}</div>)}</div>}
          <div style={{marginTop:32}}>
            <h3 style={{fontSize:15,marginBottom:12}}>Webhooks</h3>
            <div style={{padding:24,marginBottom:16}} className="card-static">
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NAME</label><input value={whForm.name} onChange={e=>setWhForm({...whForm,name:e.target.value})} placeholder="Slack Alert" style={IS}/></div>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>URL</label><input value={whForm.url} onChange={e=>setWhForm({...whForm,url:e.target.value})} placeholder="https://hooks.slack.com/..." style={IS}/></div></div>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>SECRET (optional)</label><input value={whForm.secret} onChange={e=>setWhForm({...whForm,secret:e.target.value})} placeholder="HMAC signing secret" style={IS}/></div>
                <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:6}}>EVENT TYPES</label>
                  <div style={{display:'flex',gap:6}}>{['critical','high','medium','low'].map(s=>{const a=whForm.event_types.includes(s);return <button key={s} onClick={()=>setWhForm({...whForm,event_types:a?whForm.event_types.filter(e=>e!==s):[...whForm.event_types,s]})} style={{background:a?'var(--accent-bg)':'var(--bg-primary)',border:`1px solid ${a?'rgba(0,232,123,0.3)':'var(--border-subtle)'}`,borderRadius:6,padding:'3px 8px',cursor:'pointer',color:a?'var(--accent)':'var(--text-muted)',fontSize:10,fontWeight:600,textTransform:'uppercase' as const}}>{s}</button>})}</div></div></div>
              <button onClick={createWebhook} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:'8px 20px',color:'#000',fontWeight:700,cursor:'pointer',fontSize:12}}>+ Add Webhook</button></div>
            {webhooks.length>0 && webhooks.map((wh:any)=><div key={wh.id} style={{padding:'14px 20px',marginBottom:8,display:'flex',justifyContent:'space-between',alignItems:'center'}} className="card">
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
        <div style={{padding:24,marginBottom:24}} className="card-static">
          <h3 style={{fontSize:15,marginBottom:12,display:'flex',alignItems:'center',gap:8}}>✦ Natural Language Search</h3>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:12}}>Search your indexed files using plain English queries.</p>
          <div style={{display:'flex',gap:8}}><input value={nlQuery} onChange={e=>setNlQuery(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doNlSearch(nlQuery)} placeholder="Find SQL backups in AWS that are larger than 1MB..." style={{...IS,flex:1,border:'1px solid #a855f730'}}/>
            <button onClick={()=>doNlSearch(nlQuery)} disabled={!nlQuery.trim()||sLoading} style={{background:'linear-gradient(135deg,#a855f7,#7c3aed)',border:'none',padding:'10px 20px',borderRadius:8,cursor:!nlQuery.trim()?'not-allowed':'pointer',color:'#fff',fontSize:12,fontWeight:600,opacity:!nlQuery.trim()?0.5:1}}>{sLoading?'...':'Search'}</button></div>
          {nlParsed&&<div style={{marginTop:12,display:'flex',gap:6,flexWrap:'wrap'}}>{Object.entries(nlParsed).filter(([,v])=>v).map(([k,v]:any)=><span key={k} style={{background:'#a855f710',border:'1px solid #a855f730',color:'#a855f7',padding:'2px 8px',borderRadius:4,fontSize:10}}>
            {k}: {typeof v==='object'?JSON.stringify(v):String(v)}</span>)}</div>}
        </div>

        {/* Security Report */}
        <div style={{padding:24,marginBottom:24}} className="card-static">
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
        <div style={{padding:24}} className="card-static">
          <h3 style={{fontSize:15,marginBottom:12,display:'flex',alignItems:'center',gap:8}}>✦ File Classification Overview</h3>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:16}}>AI-assigned sensitivity categories across all indexed files.</p>
          {aiClassSummary && Object.keys(aiClassSummary).length>0 ? <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:12}}>
            {Object.entries(aiClassSummary).map(([cat,cnt]:any)=><div key={cat} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:16,display:'flex',alignItems:'center',gap:10}}>
              <ClassBadge c={cat}/><span style={{fontSize:20,fontWeight:700,fontFamily:'var(--font-display)',color:'var(--text-secondary)'}}>{cnt}</span><span style={{fontSize:11,color:'var(--text-muted)'}}>files</span></div>)}
          </div> : <div style={{textAlign:'center',padding:32,color:'var(--text-muted)',fontSize:12}}>No classified files yet. Use AI Analyze on a bucket to classify its files.</div>}
        </div>
      </div>}

      {/* ─── COMPLIANCE ─── */}
      {view === 'compliance' && <div style={{maxWidth:1100,margin:'0 auto',padding:'80px 24px 24px'}}>
        <h2 style={{fontSize:24,marginBottom:20}}>☑ Compliance & Audit</h2>

        {/* Dashboard Cards */}
        {complianceDashboard && <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:16,marginBottom:24}}>
          {(Array.isArray(complianceDashboard) ? complianceDashboard : complianceDashboard.frameworks || []).map((fw:any)=><div key={fw.framework_id} onClick={async()=>{setSelectedFramework(fw);const r=await apiFetch(`/compliance/results/${fw.framework_id}`);if(Array.isArray(r))setComplianceResults(r)}} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:12,padding:16,cursor:'pointer',transition:'border-color 0.2s',borderColor:selectedFramework?.framework_id===fw.framework_id?'var(--accent)':'var(--border-default)'}}>
            <div style={{fontWeight:700,fontSize:14,marginBottom:8}}>{fw.display_name}</div>
            <div style={{fontSize:28,fontWeight:700,color:fw.score>=80?'var(--accent)':fw.score>=50?'#ffc107':'#f04848'}}>{fw.score}%</div>
            <div style={{fontSize:12,color:'var(--text-secondary)',marginTop:4}}>{fw.passed}/{fw.total_controls} controls passed</div>
            <div style={{marginTop:8,height:4,background:'var(--border-default)',borderRadius:2,overflow:'hidden'}}>
              <div style={{height:'100%',width:`${fw.score}%`,background:fw.score>=80?'var(--accent)':fw.score>=50?'#ffc107':'#f04848',borderRadius:2,transition:'width 0.3s'}}/>
            </div>
          </div>)}
        </div>}

        {/* Run Check + Export */}
        {selectedFramework && <div style={{display:'flex',gap:12,marginBottom:16}}>
          <button onClick={async()=>{const r=await apiFetch(`/compliance/check/${selectedFramework.framework_id}`,{method:'POST'});if(r?.results)setComplianceResults(r.results);loadComplianceDashboard()}} style={{padding:'8px 16px',background:'var(--accent)',color:'#000',border:'none',borderRadius:8,fontWeight:600,cursor:'pointer'}}>▶ Run Check</button>
          <button onClick={async()=>{const e=await apiFetch(`/compliance/export/${selectedFramework.framework_id}`);if(e){const blob=new Blob([JSON.stringify(e,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`compliance-${selectedFramework.name}.json`;a.click()}}} style={{padding:'8px 16px',background:'transparent',color:'var(--text-primary)',border:'1px solid var(--border-default)',borderRadius:8,fontWeight:600,cursor:'pointer'}}>⬇ Export Evidence</button>
        </div>}

        {/* Results Table */}
        {complianceResults.length > 0 && <div style={{overflow:'hidden'}} className="card-static">
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
            <thead><tr style={{background:'rgba(0,0,0,0.2)'}}>
              <th style={{padding:'10px 12px',textAlign:'left'}}>Control</th>
              <th style={{padding:'10px 12px',textAlign:'left'}}>Name</th>
              <th style={{padding:'10px 12px',textAlign:'center'}}>Status</th>
              <th style={{padding:'10px 12px',textAlign:'center'}}>Severity</th>
            </tr></thead>
            <tbody>{complianceResults.map((r:any,i:number)=><tr key={i} style={{borderTop:'1px solid var(--border-default)'}}>
              <td style={{padding:'10px 12px',fontFamily:'var(--font-mono)',fontSize:12}}>{r.control_id}</td>
              <td style={{padding:'10px 12px'}}>{r.control_name}</td>
              <td style={{padding:'10px 12px',textAlign:'center'}}><span style={{padding:'2px 8px',borderRadius:4,fontSize:11,fontWeight:700,background:r.status==='pass'?'rgba(0,255,136,0.15)':r.status==='fail'?'rgba(240,72,72,0.15)':'rgba(255,193,7,0.15)',color:r.status==='pass'?'var(--accent)':r.status==='fail'?'#f04848':'#ffc107'}}>{r.status.toUpperCase()}</span></td>
              <td style={{padding:'10px 12px',textAlign:'center'}}><span style={{fontSize:11,color:r.severity==='critical'?'#f04848':r.severity==='high'?'#fd7e14':'var(--text-secondary)'}}>{r.severity}</span></td>
            </tr>)}</tbody>
          </table>
        </div>}

        {!complianceDashboard && <div style={{textAlign:'center',padding:40,color:'var(--text-secondary)'}}>Loading compliance data...</div>}
      </div>}

      {/* ─── REMEDIATE ─── */}
      {view === 'remediate' && <div style={{maxWidth:1100,margin:'0 auto',padding:'80px 24px 24px'}}>
        <h2 style={{fontSize:24,marginBottom:20}}>✓ Remediation Tracker</h2>

        {/* Dashboard Cards */}
        <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:12,marginBottom:24}}>
          {[{label:'Open',key:'open',color:'#f04848'},{label:'In Progress',key:'in_progress',color:'#ffc107'},{label:'Verified',key:'verified',color:'var(--accent)'},{label:'Closed',key:'closed',color:'var(--text-secondary)'},{label:'Overdue',key:'overdue',color:'#fd7e14'}].map(s=><div key={s.key} style={{padding:16,textAlign:'center'}} className="card-static">
            <div style={{fontSize:28,fontWeight:700,color:s.color}}>{remDashboard[s.key]||0}</div>
            <div style={{fontSize:12,color:'var(--text-secondary)',marginTop:4}}>{s.label}</div>
          </div>)}
        </div>

        {/* Create Remediation */}
        <div style={{padding:16,marginBottom:20}} className="card-static">
          <div style={{fontWeight:700,marginBottom:12}}>Create Remediation</div>
          <form onSubmit={async(e)=>{e.preventDefault();const fd=new FormData(e.target as HTMLFormElement);const r=await apiFetch('/remediations',{method:'POST',body:JSON.stringify({bucket_id:parseInt(fd.get('bucket_id') as string)||1,title:fd.get('title'),priority:fd.get('priority')||'medium',description:fd.get('description'),due_date:fd.get('due_date')||undefined})});if(r?.id){loadRemediations();loadRemDashboard();(e.target as HTMLFormElement).reset()}}} style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr auto',gap:12,alignItems:'end'}}>
            <div><label style={{fontSize:12,color:'var(--text-secondary)'}}>Title</label><input name="title" required style={{width:'100%',padding:8,background:'var(--bg-primary)',border:'1px solid var(--border-default)',borderRadius:6,color:'var(--text-primary)'}}/></div>
            <div><label style={{fontSize:12,color:'var(--text-secondary)'}}>Priority</label><select name="priority" defaultValue="medium" style={{width:'100%',padding:8,background:'var(--bg-primary)',border:'1px solid var(--border-default)',borderRadius:6,color:'var(--text-primary)'}}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div>
            <div><label style={{fontSize:12,color:'var(--text-secondary)'}}>Due Date</label><input name="due_date" type="date" style={{width:'100%',padding:8,background:'var(--bg-primary)',border:'1px solid var(--border-default)',borderRadius:6,color:'var(--text-primary)'}}/></div>
            <button type="submit" style={{padding:'8px 16px',background:'var(--accent)',color:'#000',border:'none',borderRadius:8,fontWeight:600,cursor:'pointer'}}>+ Create</button>
          </form>
        </div>

        {/* Remediation List */}
        <div style={{overflow:'hidden'}} className="card-static">
          {bulkRems.length>0 && <div style={{display:'flex',alignItems:'center',gap:10,padding:'8px 16px',background:'var(--bg-tertiary)',borderBottom:'1px solid var(--accent)'}}>
            <span style={{fontSize:12,fontWeight:700,color:'var(--accent)'}}>{bulkRems.length} selected</span>
            <button onClick={async()=>{await apiFetch('/remediations/bulk-close',{method:'POST',body:JSON.stringify({remediation_ids:bulkRems})});setBulkRems([]);loadRemediations();loadRemDashboard()}} style={{background:'var(--accent-bg)',border:'1px solid rgba(0,232,123,0.2)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Close All</button>
            <select onChange={async(e)=>{if(!e.target.value)return;await apiFetch('/remediations/bulk-status',{method:'POST',body:JSON.stringify({remediation_ids:bulkRems,status:e.target.value})});setBulkRems([]);loadRemediations();loadRemDashboard();e.target.value=''}} style={{padding:'4px 8px',background:'var(--bg-primary)',border:'1px solid var(--border-default)',borderRadius:6,color:'var(--text-primary)',fontSize:11}} defaultValue=""><option value="" disabled>Change Status</option><option value="open">Open</option><option value="in_progress">In Progress</option><option value="verified">Verified</option><option value="closed">Closed</option></select>
            <button onClick={()=>setBulkRems([])} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:10}}>Clear</button>
          </div>}
          {remediations.items?.length === 0 ? <div style={{padding:40,textAlign:'center',color:'var(--text-secondary)'}}>No remediations yet</div> :
          remediations.items?.map((r:any)=><div key={r.id} style={{padding:'12px 16px',borderBottom:'1px solid var(--border-default)',display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <input type="checkbox" checked={bulkRems.includes(r.id)} onChange={()=>setBulkRems(prev=>prev.includes(r.id)?prev.filter(x=>x!==r.id):[...prev,r.id])} style={{width:14,height:14,accentColor:'var(--accent)',cursor:'pointer',flexShrink:0,marginRight:12}}/>
            <div style={{flex:1}}>
              <div style={{fontWeight:600,fontSize:14}}>{r.title}</div>
              <div style={{fontSize:12,color:'var(--text-secondary)',marginTop:2}}>{r.bucket_name} • {r.priority} priority • {new Date(r.created_at).toLocaleDateString()}</div>
            </div>
            <div style={{display:'flex',gap:8,alignItems:'center'}}>
              <span style={{padding:'3px 10px',borderRadius:6,fontSize:11,fontWeight:700,background:r.status==='open'?'rgba(240,72,72,0.15)':r.status==='in_progress'?'rgba(255,193,7,0.15)':r.status==='verified'?'rgba(0,255,136,0.15)':'rgba(128,128,128,0.15)',color:r.status==='open'?'#f04848':r.status==='in_progress'?'#ffc107':r.status==='verified'?'var(--accent)':'var(--text-secondary)'}}>{r.status.replace('_',' ')}</span>
              <select value={r.status} onChange={async(e)=>{await apiFetch(`/remediations/${r.id}/status`,{method:'PUT',body:JSON.stringify({status:e.target.value})});loadRemediations();loadRemDashboard()}} style={{padding:'4px 8px',background:'var(--bg-primary)',border:'1px solid var(--border-default)',borderRadius:6,color:'var(--text-primary)',fontSize:12}}>
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="verified">Verified</option>
                <option value="closed">Closed</option>
              </select>
            </div>
          </div>)}
        </div>
      </div>}

      {/* ─── SETTINGS ─── */}
      {view==='settings' && user && <div style={{padding:'80px 24px 24px',maxWidth:600,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:24}}>Account Settings</h2>
        {settingsMsg&&<div style={{background:settingsMsg.includes('fail')||settingsMsg.includes('match')?'rgba(240,72,72,0.1)':'var(--accent-bg)',border:`1px solid ${settingsMsg.includes('fail')||settingsMsg.includes('match')?'rgba(240,72,72,0.2)':'rgba(0,232,123,0.2)'}`,borderRadius:8,padding:'8px 16px',marginBottom:16,fontSize:12,color:settingsMsg.includes('fail')||settingsMsg.includes('match')?'var(--danger)':'var(--accent)'}}>{settingsMsg}</div>}
        <div style={{padding:24,marginBottom:16}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Account Info</h3>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
            {[['Email',user.email],['Username',user.username],['Tier',user.tier?.toUpperCase()],['Member Since',user.created_at?new Date(user.created_at).toLocaleDateString():'—'],['Last Login',ago(user.last_login)],['Queries Today',user.queries_today||0]].map(([l,v]:any)=><div key={l} style={{padding:12,background:'var(--bg-primary)',borderRadius:8,border:'1px solid var(--border-subtle)'}}><div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4,textTransform:'uppercase' as const}}>{l}</div><div style={{fontSize:13,color:'var(--text-primary)',fontWeight:600}}>{v}</div></div>)}
          </div>
        </div>
        <div style={{padding:24,marginBottom:16}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>API Key</h3>
          <div style={{display:'flex',alignItems:'center',gap:12}}>
            <div style={{flex:1,background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:'10px 14px',fontFamily:'var(--font-mono)',fontSize:12,color:'var(--text-secondary)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{showApiKey?user.api_key:'ba_••••••••••••••••••••••••••••••'}</div>
            <button onClick={()=>setShowApiKey(!showApiKey)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-muted)',padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:11}}>{showApiKey?'Hide':'Show'}</button>
            <button onClick={()=>{navigator.clipboard.writeText(user.api_key);setCopiedKey(true);setTimeout(()=>setCopiedKey(false),2000)}} style={{background:copiedKey?'var(--accent-bg)':'var(--bg-primary)',border:`1px solid ${copiedKey?'rgba(0,232,123,0.3)':'var(--border-subtle)'}`,color:copiedKey?'var(--accent)':'var(--text-muted)',padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:11,transition:'all 0.2s'}}>{copiedKey?'Copied!':'Copy'}</button>
            <button onClick={rotateApiKey} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--warning)',padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:11}}>Rotate</button>
          </div>
        </div>
        <div style={{padding:24}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Update Profile</h3>
          <div style={{marginBottom:12}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NEW USERNAME</label>
            <input value={settingsForm.username} onChange={e=>setSettingsForm({...settingsForm,username:e.target.value})} placeholder={user.username} style={IS}/></div>
          <div style={{marginBottom:12}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>NEW PASSWORD</label>
            <input type="password" value={settingsForm.password} onChange={e=>setSettingsForm({...settingsForm,password:e.target.value})} placeholder="Leave blank to keep current" style={IS}/></div>
          <div style={{marginBottom:16}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>CONFIRM PASSWORD</label>
            <input type="password" value={settingsForm.confirmPassword} onChange={e=>setSettingsForm({...settingsForm,confirmPassword:e.target.value})} placeholder="Confirm new password" style={IS}/></div>
          <button onClick={updateSettings} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:'10px 24px',color:'#000',fontWeight:700,cursor:'pointer',fontSize:12}}>Save Changes</button>
        </div>

        {/* Two-Factor Authentication */}
        <div style={{padding:24,marginTop:16}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:4,color:'var(--text-secondary)'}}>Two-Factor Authentication</h3>
          <p style={{fontSize:11,color:'var(--text-muted)',margin:'0 0 16px'}}>Add an extra layer of security to your account with TOTP-based 2FA.</p>
          {!twoFaStatus ? <button onClick={load2faStatus} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:12,fontWeight:600}}>Check 2FA Status</button>
          : twoFaStatus.enabled ? <div>
            <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:12}}>
              <span style={{background:'rgba(0,232,123,0.15)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,fontSize:12,fontWeight:700}}>ENABLED</span>
              <span style={{fontSize:11,color:'var(--text-muted)'}}>{twoFaStatus.backup_codes_remaining} backup codes remaining</span>
            </div>
            <button onClick={async()=>{const pw=prompt('Enter your password to disable 2FA:');if(!pw)return;const r=await apiFetch('/auth/2fa/disable',{method:'POST',body:JSON.stringify({password:pw})});if(r?.message){toast('2FA disabled','success');load2faStatus()}else{toast(r?.error||'Failed','error')}}} style={{background:'rgba(240,72,72,0.1)',border:'1px solid rgba(240,72,72,0.2)',color:'#f04848',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:12,fontWeight:600}}>Disable 2FA</button>
          </div>
          : <div>
            <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:12}}>
              <span style={{background:'rgba(240,72,72,0.15)',color:'#f04848',padding:'4px 12px',borderRadius:6,fontSize:12,fontWeight:700}}>NOT ENABLED</span>
            </div>
            {!twoFaSetup ? <button onClick={async()=>{const r=await apiFetch('/auth/2fa/setup',{method:'POST'});if(r?.secret)setTwoFaSetup(r);else toast(r?.error||'Setup failed','error')}} style={{background:'var(--accent)',border:'none',color:'#000',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:12,fontWeight:700}}>Enable 2FA</button>
            : <div style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:16}}>
              <div style={{fontSize:12,color:'var(--text-secondary)',marginBottom:8}}>Add this secret to your authenticator app:</div>
              <div style={{background:'var(--bg-secondary)',padding:'8px 12px',borderRadius:6,fontFamily:'var(--font-mono)',fontSize:13,fontWeight:600,color:'var(--accent)',marginBottom:12,wordBreak:'break-all' as const}}>{twoFaSetup.secret}</div>
              <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:12}}>Or use the URI: <code style={{fontSize:10}}>{twoFaSetup.otpauth_uri}</code></div>
              <div style={{display:'flex',gap:8,alignItems:'center'}}>
                <input value={twoFaCode} onChange={e=>setTwoFaCode(e.target.value)} placeholder="Enter 6-digit code" maxLength={6} style={{...IS,width:160,padding:'8px 12px'}}
                  onKeyDown={e=>{if(e.key==='Enter'&&twoFaCode.length===6){(async()=>{const r=await apiFetch('/auth/2fa/confirm',{method:'POST',body:JSON.stringify({code:twoFaCode})});if(r?.backup_codes){toast('2FA enabled!','success');setTwoFaSetup(null);setTwoFaCode('');load2faStatus();setModal({title:'Backup Codes',msg:'Save these codes securely. Each can be used once:\n\n'+r.backup_codes.join('  '),onConfirm:()=>{}})}else{toast(r?.error||'Invalid code','error')}})()}}}/>
                <button onClick={async()=>{const r=await apiFetch('/auth/2fa/confirm',{method:'POST',body:JSON.stringify({code:twoFaCode})});if(r?.backup_codes){toast('2FA enabled!','success');setTwoFaSetup(null);setTwoFaCode('');load2faStatus();setModal({title:'Backup Codes',msg:'Save these codes securely. Each can be used once:\n\n'+r.backup_codes.join('  '),onConfirm:()=>{}})}else{toast(r?.error||'Invalid code','error')}}} disabled={twoFaCode.length!==6} style={{background:twoFaCode.length===6?'var(--accent)':'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:twoFaCode.length===6?'#000':'var(--text-muted)',padding:'8px 16px',borderRadius:8,cursor:twoFaCode.length===6?'pointer':'not-allowed',fontSize:12,fontWeight:600}}>Verify & Enable</button>
              </div>
            </div>}
          </div>}
        </div>

        {/* Organizations */}
        <div style={{padding:24,marginTop:16}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Organizations</h3>
          <form onSubmit={async(e:any)=>{e.preventDefault();const name=e.target.orgName.value.trim();if(!name)return;const slug=name.toLowerCase().replace(/[^a-z0-9]/g,'-');const r=await apiFetch('/orgs',{method:'POST',body:JSON.stringify({name,slug})});if(r?.id)loadOrgs();e.target.reset()}} style={{display:'flex',gap:8,marginBottom:12}}>
            <input name="orgName" placeholder="Organization name" required style={{flex:1,padding:'8px 12px',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,color:'var(--text-primary)',fontSize:12}}/>
            <button type="submit" style={{background:'var(--accent)',color:'#000',border:'none',borderRadius:8,padding:'8px 14px',fontWeight:600,cursor:'pointer',fontSize:12}}>Create</button>
          </form>
          {orgs.length===0?<div style={{fontSize:12,color:'var(--text-muted)',padding:'8px 0'}}>No organizations yet.</div>:
          orgs.map((o:any)=><div key={o.id} style={{padding:'8px 0',borderTop:'1px solid var(--border-subtle)',display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <span style={{fontWeight:600,fontSize:13}}>{o.name} <span style={{fontSize:10,color:'var(--text-muted)'}}>({o.slug})</span></span>
          </div>)}
        </div>

        {/* Integrations */}
        <div style={{padding:24,marginTop:16}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Integrations</h3>
          <div style={{display:'flex',gap:12,flexWrap:'wrap' as const,marginBottom:12}}>
            {(['slack','jira'] as const).map(t=><div key={t} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:16,flex:'1 1 180px'}}>
              <div style={{fontWeight:700,textTransform:'capitalize' as const,marginBottom:4,fontSize:13}}>{t}</div>
              <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:8}}>{integrations.filter((i:any)=>i.type===t).length} configured</div>
              <button onClick={()=>{setModalInput('');setModal({title:`Add ${t} Integration`,msg:`Enter ${t==='slack'?'webhook URL':'base URL'}:`,input:true,onConfirm:()=>{if(modalInput.trim()){apiFetch('/integrations',{method:'POST',body:JSON.stringify({type:t,name:`My ${t}`,config:t==='slack'?{webhook_url:modalInput}:{base_url:modalInput,email:'',api_token:'',project_key:''}})}).then(()=>{loadIntegrations();toast('Integration added','success')})}}})}} style={{padding:'5px 10px',background:'var(--accent)',color:'#000',border:'none',borderRadius:6,fontSize:11,fontWeight:600,cursor:'pointer'}}>+ Add</button>
            </div>)}
          </div>
          {integrations.map((i:any)=><div key={i.id} style={{marginTop:8,padding:'8px 12px',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <span style={{fontSize:12}}>{i.name} <span style={{fontSize:10,color:'var(--text-muted)'}}>({i.type})</span></span>
            <div style={{display:'flex',gap:6}}>
              <button onClick={async()=>{const r=await apiFetch(`/integrations/${i.id}/test`,{method:'POST'});toast(r?.success?'Integration test passed!':'Test failed: '+(r?.error||'Unknown'),r?.success?'success':'error')}} style={{padding:'3px 8px',border:'1px solid var(--border-subtle)',background:'none',color:'var(--text-secondary)',borderRadius:4,fontSize:10,cursor:'pointer'}}>Test</button>
              <button onClick={async()=>{await apiFetch(`/integrations/${i.id}`,{method:'DELETE'});loadIntegrations()}} style={{padding:'3px 8px',border:'1px solid var(--border-subtle)',background:'none',color:'var(--danger)',borderRadius:4,fontSize:10,cursor:'pointer'}}>Delete</button>
            </div>
          </div>)}
        </div>

        {/* Tags */}
        <div style={{padding:24,marginTop:16}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:4,color:'var(--text-secondary)'}}>Tags</h3>
          <p style={{fontSize:11,color:'var(--text-muted)',margin:'0 0 16px'}}>Create tags to organize and categorize your buckets.</p>
          <div style={{display:'flex',gap:8,marginBottom:16,alignItems:'end'}}>
            <div style={{flex:1}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>TAG NAME</label><input value={tagForm.name} onChange={e=>setTagForm({...tagForm,name:e.target.value})} placeholder="e.g. production, sensitive" style={{...IS,padding:'8px 12px'}}/></div>
            <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>COLOR</label><input type="color" value={tagForm.color} onChange={e=>setTagForm({...tagForm,color:e.target.value})} style={{width:40,height:38,padding:2,background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,cursor:'pointer'}}/></div>
            <button onClick={async()=>{if(!tagForm.name.trim())return;await apiFetch('/tags',{method:'POST',body:JSON.stringify(tagForm)});setTagForm({name:'',color:'#6b7280'});loadTags()}} style={{background:'var(--accent)',color:'#000',border:'none',borderRadius:8,padding:'8px 14px',fontWeight:600,cursor:'pointer',fontSize:12,whiteSpace:'nowrap' as const}}>Create</button>
          </div>
          {tags.length===0?<div style={{fontSize:12,color:'var(--text-muted)',padding:'8px 0'}}>No tags created yet.</div>:
          <div style={{display:'flex',flexDirection:'column',gap:6}}>
            {tags.map((t:any)=><div key={t.id} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 12px',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8}}>
              <div style={{display:'flex',alignItems:'center',gap:8}}>
                <div style={{width:10,height:10,borderRadius:'50%',background:t.color,flexShrink:0}}/>
                <span style={{fontSize:13,fontWeight:600,color:'var(--text-primary)'}}>{t.name}</span>
                <span style={{background:t.color+'20',color:t.color,border:`1px solid ${t.color}40`,padding:'1px 6px',borderRadius:10,fontSize:9,fontWeight:600}}>{t.name}</span>
              </div>
              <div style={{display:'flex',gap:6}}>
                <button onClick={()=>{setModalInput(t.name);setModal({title:'Rename Tag',msg:'Enter new name:',input:true,onConfirm:async()=>{if(modalInput.trim()&&modalInput!==t.name){await apiFetch(`/tags/${t.id}`,{method:'PUT',body:JSON.stringify({name:modalInput})});loadTags();toast('Tag renamed','success')}}})}} style={{padding:'3px 8px',border:'1px solid var(--border-subtle)',background:'none',color:'var(--text-secondary)',borderRadius:4,fontSize:10,cursor:'pointer'}}>Edit</button>
                <button onClick={async()=>{await apiFetch(`/tags/${t.id}`,{method:'DELETE'});loadTags()}} style={{padding:'3px 8px',border:'1px solid var(--border-subtle)',background:'none',color:'var(--danger)',borderRadius:4,fontSize:10,cursor:'pointer'}}>Delete</button>
              </div>
            </div>)}
          </div>}
        </div>

        {/* Audit Log */}
        <div style={{padding:24,marginTop:16}} className="card-static">
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16}}>
            <div><h3 style={{fontSize:14,margin:0,color:'var(--text-secondary)'}}>Audit Log</h3><p style={{fontSize:11,color:'var(--text-muted)',margin:'4px 0 0'}}>Track all changes and actions in your account.</p></div>
            <button onClick={()=>loadAuditLog(1)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'5px 12px',borderRadius:6,cursor:'pointer',fontSize:10,fontWeight:600}}>Load Log</button>
          </div>
          {auditLog.items.length>0 && <>
            <div style={{display:'grid',gridTemplateColumns:'130px 80px 120px 1fr',gap:8,padding:'6px 12px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,letterSpacing:'0.5px',borderBottom:'1px solid var(--border-subtle)'}}><span>Timestamp</span><span>Action</span><span>Entity</span><span>Details</span></div>
            {auditLog.items.map((e:any,i:number)=>{const ac:any={create:{bg:'rgba(0,255,136,0.12)',c:'var(--accent)'},update:{bg:'rgba(74,158,255,0.12)',c:'#4a9eff'},delete:{bg:'rgba(240,72,72,0.12)',c:'#f04848'}};const s=ac[e.action]||{bg:'var(--bg-primary)',c:'var(--text-muted)'};return <div key={e.id||i} style={{display:'grid',gridTemplateColumns:'130px 80px 120px 1fr',gap:8,padding:'8px 12px',alignItems:'center',background:i%2===0?'var(--bg-primary)':'transparent',borderRadius:4}}>
              <span style={{fontSize:10,color:'var(--text-muted)',fontFamily:'var(--font-mono)'}}>{e.created_at?new Date(e.created_at).toLocaleString():e.timestamp?new Date(e.timestamp).toLocaleString():'—'}</span>
              <span style={{background:s.bg,color:s.c,padding:'2px 8px',borderRadius:4,fontSize:9,fontWeight:700,textTransform:'uppercase' as const,textAlign:'center' as const}}>{e.action}</span>
              <span style={{fontSize:11,color:'var(--text-secondary)'}}>{e.entity_type}{e.entity_id?` #${e.entity_id}`:''}</span>
              <span style={{fontSize:11,color:'var(--text-muted)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{typeof e.details==='object'?JSON.stringify(e.details):e.details||'—'}</span>
            </div>})}
            {auditLog.total>auditLog.items.length && <div style={{textAlign:'center',marginTop:12}}>
              <button onClick={()=>loadAuditLog(Math.floor(auditLog.items.length/50)+1)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'6px 16px',borderRadius:6,cursor:'pointer',fontSize:11,fontWeight:600}}>Load More ({auditLog.total - auditLog.items.length} remaining)</button>
            </div>}
          </>}
          {auditLog.items.length===0 && <div style={{textAlign:'center',padding:16,color:'var(--text-muted)',fontSize:12}}>Click "Load Log" to view audit trail.</div>}
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

      {/* ─── DRIFT DETECTION ─── */}
      {view==='drift' && <div style={{padding:'80px 24px 24px',maxWidth:1100,margin:'0 auto'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:24}}>
          <div><h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>Scan Drift Detection</h2>
            <p style={{fontSize:13,color:'var(--text-tertiary)',margin:'4px 0 0'}}>Track changes between scans — new buckets, status changes, file additions.</p></div>
        </div>
        {/* Summary cards */}
        {driftSummary && <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:24}}>
          {[['Total Changes',driftSummary.total,'var(--text-primary)'],['Unreviewed',driftSummary.unreviewed,'var(--warning)'],['Critical',driftSummary.by_severity?.critical||0,'#f04848'],['High',driftSummary.by_severity?.high||0,'#ff6b35']].map(([l,v,c]:any)=>
            <div key={l} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:10,padding:16,textAlign:'center'}}>
              <div style={{fontSize:24,fontWeight:800,color:c,fontFamily:'var(--font-display)'}}>{v}</div>
              <div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>{l}</div></div>)}
        </div>}
        {driftSummary?.by_type && <div style={{display:'flex',gap:8,marginBottom:16,flexWrap:'wrap' as const}}>
          {Object.entries(driftSummary.by_type).map(([t,c]:any)=>
            <span key={t} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',padding:'4px 10px',borderRadius:6,fontSize:11,color:'var(--text-secondary)'}}>{t.replace(/_/g,' ')}: <b>{c}</b></span>)}
        </div>}
        {/* Filters */}
        <div style={{display:'flex',gap:8,marginBottom:16,alignItems:'center'}}>
          <select value={driftFilter.severity} onChange={e=>{setDriftFilter({...driftFilter,severity:e.target.value});setTimeout(()=>loadDriftDiffs(),0)}} style={{...IS,width:140,padding:'6px 10px'}}>
            <option value="">All severities</option>
            {['critical','high','medium','low','info'].map(s=><option key={s} value={s}>{s}</option>)}
          </select>
          <label style={{display:'flex',alignItems:'center',gap:6,fontSize:12,color:'var(--text-secondary)',cursor:'pointer'}}>
            <input type="checkbox" checked={driftFilter.unreviewed} onChange={e=>{setDriftFilter({...driftFilter,unreviewed:e.target.checked});setTimeout(()=>loadDriftDiffs(),0)}}/>
            Unreviewed only
          </label>
          <button onClick={()=>loadDriftDiffs()} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'6px 14px',borderRadius:6,cursor:'pointer',fontSize:11,fontWeight:600}}>Refresh</button>
        </div>
        {/* Diff list */}
        {driftDiffs.items?.length===0 ? <div style={{textAlign:'center',padding:60,color:'var(--text-muted)'}}>
          <div style={{fontSize:48,marginBottom:16}}>△</div>
          <div style={{fontSize:16,fontWeight:600,marginBottom:8}}>No drift detected yet</div>
          <div style={{fontSize:13}}>Run scans to start tracking changes across your monitored buckets.</div>
        </div>
        : <div style={{display:'flex',flexDirection:'column',gap:8}}>
          {driftDiffs.items?.map((d:any)=><div key={d.id} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:10,padding:16,display:'flex',alignItems:'center',gap:12}}>
            <div style={{width:40,height:40,borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center',fontSize:18,flexShrink:0,
              background:d.diff_type==='new_bucket'?'rgba(0,232,123,0.1)':d.diff_type==='status_change'?'rgba(240,72,72,0.1)':d.diff_type==='files_added'?'rgba(74,158,255,0.1)':'rgba(245,166,35,0.1)',
              color:d.diff_type==='new_bucket'?'var(--accent)':d.diff_type==='status_change'?'#f04848':d.diff_type==='files_added'?'#4a9eff':'#f5a623',
            }}>{d.diff_type==='new_bucket'?'+':d.diff_type==='status_change'?'⇄':d.diff_type==='files_added'?'↑':d.diff_type==='files_removed'?'↓':'◇'}</div>
            <div style={{flex:1,minWidth:0}}>
              <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
                <span style={{fontWeight:600,fontSize:13}}>{d.bucket_name||'—'}</span>
                {d.provider_name && <Badge provider={d.provider_name}/>}
                <SevBadge s={d.severity}/>
                <span style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',padding:'1px 6px',borderRadius:4,fontSize:9,color:'var(--text-muted)'}}>{d.diff_type.replace(/_/g,' ')}</span>
                {d.is_reviewed && <span style={{fontSize:9,color:'var(--text-muted)'}}>reviewed</span>}
              </div>
              <div style={{fontSize:12,color:'var(--text-secondary)'}}>{d.summary}</div>
              <div style={{fontSize:10,color:'var(--text-muted)',marginTop:4}}>{d.created_at?new Date(d.created_at).toLocaleString():'—'}</div>
            </div>
            {!d.is_reviewed && <button onClick={async()=>{await apiFetch(`/drift/diffs/${d.id}/review`,{method:'POST'});loadDriftDiffs();loadDriftSummary()}} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'6px 12px',borderRadius:6,cursor:'pointer',fontSize:11,fontWeight:600,flexShrink:0}}>Review</button>}
          </div>)}
        </div>}
        {driftDiffs.total>driftDiffs.items?.length && <div style={{textAlign:'center',marginTop:16}}>
          <button onClick={()=>loadDriftDiffs(Math.floor(driftDiffs.items.length/50)+1)} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'8px 20px',borderRadius:8,cursor:'pointer',fontSize:12,fontWeight:600}}>Load More</button>
        </div>}
      </div>}

      {/* ─── CUSTOM ALERT RULES ─── */}
      {view==='rules' && <div style={{padding:'80px 24px 24px',maxWidth:900,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Custom Alert Rules</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24}}>Define your own rules to get alerted when buckets or files match your criteria.</p>

        {/* Create Rule Form */}
        <div style={{padding:24,marginBottom:24}} className="card-static">
          <h3 style={{fontSize:14,marginBottom:16,color:'var(--text-secondary)'}}>Create Rule</h3>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
            <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>RULE NAME</label>
              <input value={ruleForm.name} onChange={e=>setRuleForm({...ruleForm,name:e.target.value})} placeholder="e.g. Large SQL files" style={{...IS,padding:'8px 12px'}}/></div>
            <div><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>SEVERITY</label>
              <select value={ruleForm.severity} onChange={e=>setRuleForm({...ruleForm,severity:e.target.value})} style={{...IS,padding:'8px 12px'}}>
                {['critical','high','medium','low','info'].map(s=><option key={s} value={s}>{s}</option>)}</select></div>
          </div>
          <div style={{marginBottom:12}}><label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>DESCRIPTION</label>
            <input value={ruleForm.description} onChange={e=>setRuleForm({...ruleForm,description:e.target.value})} placeholder="Optional description" style={{...IS,padding:'8px 12px'}}/></div>

          {/* Conditions */}
          <div style={{marginBottom:12}}>
            <label style={{fontSize:10,color:'var(--text-muted)',display:'block',marginBottom:4}}>CONDITIONS ({ruleForm.conditions.length})</label>
            {ruleForm.conditions.map((c:any,i:number)=><div key={i} style={{display:'flex',gap:8,alignItems:'center',marginBottom:4,padding:'4px 8px',background:'var(--bg-primary)',borderRadius:6,border:'1px solid var(--border-subtle)'}}>
              <span style={{fontSize:11,color:'var(--accent)',fontWeight:600}}>{c.type}</span>
              <span style={{fontSize:11,color:'var(--text-secondary)'}}>= {c.value}</span>
              <button onClick={()=>setRuleForm({...ruleForm,conditions:ruleForm.conditions.filter((_:any,j:number)=>j!==i)})} style={{marginLeft:'auto',background:'none',border:'none',color:'var(--danger)',cursor:'pointer',fontSize:14}}>×</button>
            </div>)}
            <div style={{display:'flex',gap:8,marginTop:8}}>
              <select value={ruleForm.condType} onChange={e=>setRuleForm({...ruleForm,condType:e.target.value})} style={{...IS,width:180,padding:'6px 10px',fontSize:11}}>
                <option value="file_extension">File extension</option>
                <option value="file_size_gt">File size greater than (bytes)</option>
                <option value="file_name_contains">Filename contains</option>
                <option value="bucket_name_contains">Bucket name contains</option>
                <option value="bucket_status">Bucket status</option>
                <option value="provider">Provider</option>
                <option value="file_count_gt">File count greater than</option>
                <option value="classification">AI classification</option>
              </select>
              <input value={ruleForm.condValue} onChange={e=>setRuleForm({...ruleForm,condValue:e.target.value})} placeholder="Value" style={{...IS,flex:1,padding:'6px 10px',fontSize:11}}
                onKeyDown={e=>{if(e.key==='Enter'&&ruleForm.condValue.trim()){setRuleForm({...ruleForm,conditions:[...ruleForm.conditions,{type:ruleForm.condType,value:ruleForm.condValue}],condValue:''})}}}/>
              <button onClick={()=>{if(!ruleForm.condValue.trim())return;setRuleForm({...ruleForm,conditions:[...ruleForm.conditions,{type:ruleForm.condType,value:ruleForm.condValue}],condValue:''})}} style={{background:'var(--accent)',color:'#000',border:'none',borderRadius:6,padding:'6px 12px',fontSize:11,fontWeight:600,cursor:'pointer',whiteSpace:'nowrap' as const}}>+ Add</button>
            </div>
          </div>

          <button onClick={async()=>{if(!ruleForm.name.trim()||!ruleForm.conditions.length){toast('Name and at least one condition required','error');return}; const r=await apiFetch('/alert-rules',{method:'POST',body:JSON.stringify({name:ruleForm.name,description:ruleForm.description,severity:ruleForm.severity,conditions:ruleForm.conditions})}); if(r?.id){toast('Rule created','success');setRuleForm({name:'',description:'',severity:'medium',conditions:[],condType:'file_extension',condValue:''});loadAlertRules()}else{toast(r?.error||'Failed','error')}}} style={{background:'linear-gradient(135deg,var(--accent),#00c568)',border:'none',borderRadius:8,padding:'10px 24px',color:'#000',fontWeight:700,cursor:'pointer',fontSize:12}}>Create Rule</button>
        </div>

        {/* Rules List */}
        {alertRules.length===0 ? <div style={{textAlign:'center',padding:40,color:'var(--text-muted)',fontSize:13}}>No custom alert rules yet. Create one above.</div>
        : alertRules.map((r:any)=>{const conds=typeof r.conditions==='string'?JSON.parse(r.conditions):r.conditions;return <div key={r.id} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:10,padding:16,marginBottom:8,display:'flex',alignItems:'center',gap:12}}>
          <div style={{flex:1}}>
            <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
              <span style={{fontWeight:700,fontSize:14}}>{r.name}</span>
              <SevBadge s={r.severity}/>
              <span style={{background:r.is_active?'rgba(0,232,123,0.15)':'rgba(240,72,72,0.15)',color:r.is_active?'var(--accent)':'#f04848',padding:'2px 8px',borderRadius:4,fontSize:9,fontWeight:700}}>{r.is_active?'ACTIVE':'DISABLED'}</span>
              <span style={{fontSize:10,color:'var(--text-muted)'}}>{r.match_count} matches</span>
            </div>
            {r.description && <div style={{fontSize:12,color:'var(--text-secondary)',marginBottom:6}}>{r.description}</div>}
            <div style={{display:'flex',gap:6,flexWrap:'wrap' as const}}>
              {conds.map((c:any,i:number)=><span key={i} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',padding:'2px 8px',borderRadius:4,fontSize:10,color:'var(--text-secondary)'}}>{c.type}: <b>{c.value}</b></span>)}
            </div>
            {r.last_matched_at && <div style={{fontSize:10,color:'var(--text-muted)',marginTop:4}}>Last match: {ago(r.last_matched_at)}</div>}
          </div>
          <div style={{display:'flex',gap:6,flexShrink:0}}>
            <button onClick={async()=>{await apiFetch(`/alert-rules/${r.id}/toggle`,{method:'POST'});loadAlertRules()}} style={{padding:'5px 10px',border:'1px solid var(--border-subtle)',background:'none',color:'var(--text-secondary)',borderRadius:6,fontSize:10,cursor:'pointer'}}>{r.is_active?'Disable':'Enable'}</button>
            <button onClick={async()=>{await apiFetch(`/alert-rules/${r.id}`,{method:'DELETE'});loadAlertRules();toast('Rule deleted','success')}} style={{padding:'5px 10px',border:'1px solid var(--border-subtle)',background:'none',color:'var(--danger)',borderRadius:6,fontSize:10,cursor:'pointer'}}>Delete</button>
          </div>
        </div>})}
      </div>}

      {/* ─── EXECUTIVE DASHBOARD ─── */}
      {view==='dashboard' && <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:8}}>Executive Dashboard</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:24}}>High-level security posture overview with risk trends and SLA tracking.</p>

        {!execDash ? <Spin/> : <>
          {/* Top-level KPIs */}
          <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:12,marginBottom:24}}>
            {[['Total Buckets',execDash.total_buckets,'var(--text-primary)'],['Open Buckets',execDash.open_buckets,'#f04848'],['Exposure Rate',execDash.exposure_rate+'%',execDash.exposure_rate>20?'#f04848':execDash.exposure_rate>5?'#f5a623':'var(--accent)'],['Total Files',fnum(execDash.total_files),'var(--text-primary)'],['Data Exposed',fmt(execDash.total_size_bytes),'var(--warning)']].map(([l,v,c]:any)=>
              <div key={l} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-default)',borderRadius:10,padding:16,textAlign:'center'}}>
                <div style={{fontSize:24,fontWeight:800,color:c,fontFamily:'var(--font-display)'}}>{v}</div>
                <div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>{l}</div></div>)}
          </div>

          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:24}}>
            {/* Risk Distribution */}
            <div style={{padding:20}} className="card-static">
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Risk Distribution</h3>
              {execDash.risk_distribution && Object.entries(execDash.risk_distribution).length>0 ?
                Object.entries(execDash.risk_distribution).map(([level,count]:any)=>{const c:any={critical:'#f04848',high:'#ff6b35',medium:'#f5a623',low:'#4a9eff',info:'#4a5f73'};return <div key={level} style={{display:'flex',alignItems:'center',gap:8,marginBottom:8}}>
                  <div style={{width:80,fontSize:11,fontWeight:600,textTransform:'capitalize' as const,color:c[level]||'var(--text-secondary)'}}>{level}</div>
                  <div style={{flex:1,height:8,background:'var(--bg-primary)',borderRadius:4,overflow:'hidden'}}><div style={{height:'100%',background:c[level]||'var(--text-muted)',borderRadius:4,width:`${Math.min(100,count/(execDash.total_buckets||1)*100)}%`}}/></div>
                  <span style={{fontSize:12,fontWeight:600,width:40,textAlign:'right' as const}}>{count}</span>
                </div>})
              : <div style={{color:'var(--text-muted)',fontSize:12}}>No risk data yet. Run AI risk assessments on your buckets.</div>}
            </div>

            {/* Unresolved Alerts */}
            <div style={{padding:20}} className="card-static">
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Unresolved Alerts</h3>
              {execDash.unresolved_alerts && Object.entries(execDash.unresolved_alerts).length>0 ?
                Object.entries(execDash.unresolved_alerts).map(([sev,count]:any)=><div key={sev} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                  <SevBadge s={sev}/><span style={{fontSize:14,fontWeight:700}}>{count}</span></div>)
              : <div style={{color:'var(--text-muted)',fontSize:12}}>No unresolved alerts.</div>}
            </div>
          </div>

          {/* Sensitive Files */}
          {execDash.sensitive_files && Object.keys(execDash.sensitive_files).length>0 && <div style={{padding:20,marginBottom:24}} className="card-static">
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Sensitive Files Detected</h3>
            <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12}}>
              {Object.entries(execDash.sensitive_files).map(([cls,count]:any)=><div key={cls} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:12,textAlign:'center'}}>
                <ClassBadge c={cls}/><div style={{fontSize:20,fontWeight:800,marginTop:8,color:'var(--text-primary)'}}>{count}</div></div>)}
            </div>
          </div>}

          {/* Drift Summary */}
          {execDash.drift_summary && <div style={{padding:20,marginBottom:24}} className="card-static">
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
              <h3 style={{fontSize:14,fontWeight:700,margin:0}}>Drift Summary</h3>
              <button onClick={()=>{setView('drift');loadDriftDiffs();loadDriftSummary()}} style={{background:'none',border:'1px solid var(--border-subtle)',color:'var(--accent)',padding:'4px 12px',borderRadius:6,cursor:'pointer',fontSize:11}}>View All →</button>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12}}>
              {[['Total Changes',execDash.drift_summary.total],['Unreviewed',execDash.drift_summary.unreviewed],['Critical',execDash.drift_summary.by_severity?.critical||0],['High',execDash.drift_summary.by_severity?.high||0]].map(([l,v]:any)=>
                <div key={l} style={{textAlign:'center',padding:12,background:'var(--bg-primary)',borderRadius:8,border:'1px solid var(--border-subtle)'}}>
                  <div style={{fontSize:20,fontWeight:800}}>{v}</div><div style={{fontSize:10,color:'var(--text-muted)',marginTop:2}}>{l}</div></div>)}
            </div>
          </div>}

          {/* Risk Trends Chart */}
          {riskTrends?.risk_trends?.length>0 && <div style={{padding:20,marginBottom:24}} className="card-static">
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Scan Activity Trends (30 days)</h3>
            <div style={{display:'flex',alignItems:'end',gap:2,height:120,padding:'0 4px'}}>
              {riskTrends.risk_trends.map((d:any,i:number)=>{const maxFiles=Math.max(...riskTrends.risk_trends.map((x:any)=>x.total_files||0),1);const h=Math.max(4,((d.total_files||0)/maxFiles)*100);return <div key={i} style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',gap:2}} title={`${d.day}: ${d.total_files||0} files, ${d.open_count||0} open`}>
                <div style={{width:'100%',height:h,background:d.open_count>0?'linear-gradient(180deg,#f04848,#ff6b35)':'linear-gradient(180deg,var(--accent),#00c568)',borderRadius:'2px 2px 0 0',minHeight:4,transition:'height 0.3s'}}/>
              </div>})}
            </div>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:9,color:'var(--text-muted)',marginTop:4}}>
              <span>{riskTrends.risk_trends[0]?.day}</span><span>{riskTrends.risk_trends[riskTrends.risk_trends.length-1]?.day}</span>
            </div>
          </div>}

          {/* Remediation SLA */}
          {remSla && <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:24}}>
            <div style={{padding:20}} className="card-static">
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Remediation SLA</h3>
              {remSla.time_to_close && Object.entries(remSla.time_to_close).length>0 ?
                Object.entries(remSla.time_to_close).map(([pri,data]:any)=><div key={pri} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                  <span style={{fontSize:12,fontWeight:600,textTransform:'capitalize' as const}}>{pri}</span>
                  <span style={{fontSize:12,color:'var(--text-secondary)'}}>Avg {data.avg_days}d ({data.count} closed)</span></div>)
              : <div style={{color:'var(--text-muted)',fontSize:12}}>No completed remediations yet.</div>}
            </div>
            <div style={{padding:20}} className="card-static">
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Open Remediation Aging</h3>
              {remSla.open_aging ? <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
                {[['< 7 days',remSla.open_aging.this_week,'var(--accent)'],['7-30 days',remSla.open_aging.this_month,'var(--warning)'],['> 30 days',remSla.open_aging.older,'#f04848']].map(([l,v,c]:any)=>
                  <div key={l} style={{textAlign:'center',padding:12,background:'var(--bg-primary)',borderRadius:8}}>
                    <div style={{fontSize:20,fontWeight:800,color:c}}>{v||0}</div><div style={{fontSize:10,color:'var(--text-muted)',marginTop:2}}>{l}</div></div>)}
              </div> : <div style={{color:'var(--text-muted)',fontSize:12}}>No open remediations.</div>}
            </div>
          </div>}

          {/* Top Exposed Buckets */}
          {execDash.top_exposed_buckets?.length>0 && <div style={{padding:20}} className="card-static">
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Top Exposed Buckets</h3>
            <div style={{display:'grid',gridTemplateColumns:'2fr 80px 80px 80px',gap:8,padding:'6px 12px',fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase' as const,borderBottom:'1px solid var(--border-subtle)'}}><span>Bucket</span><span>Files</span><span>Status</span><span>Risk</span></div>
            {execDash.top_exposed_buckets.map((b:any,i:number)=><div key={i} style={{display:'grid',gridTemplateColumns:'2fr 80px 80px 80px',gap:8,padding:'8px 12px',alignItems:'center',background:i%2===0?'var(--bg-primary)':'transparent',borderRadius:4}}>
              <span style={{fontSize:12,fontWeight:600,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' as const}}>{b.name}</span>
              <span style={{fontSize:12}}>{fnum(b.file_count)}</span>
              <SBadge s={b.status}/>
              {b.risk_score!=null ? <RiskBadge score={b.risk_score} level={b.risk_level||'info'}/> : <span style={{fontSize:10,color:'var(--text-muted)'}}>—</span>}
            </div>)}
          </div>}
        </>}
      </div>}

      {/* ─── API DOCS ─── */}
      {view==='api-docs' && (()=>{
        const MC:any={GET:{bg:'var(--accent-bg)',c:'var(--accent)',bc:'rgba(0,232,123,0.2)'},POST:{bg:'#ff990015',c:'#ff9900',bc:'rgba(255,153,0,0.2)'},PUT:{bg:'#4a9eff15',c:'#4a9eff',bc:'rgba(74,158,255,0.2)'},DELETE:{bg:'#f0484815',c:'#f04848',bc:'rgba(240,72,72,0.2)'}}
        const endpoints:any[]=[
          {tag:'Auth',m:'POST',p:'/auth/register',d:'Create a new account',auth:'none',
            params:[{n:'email',t:'string',r:true,d:'User email address'},{n:'username',t:'string',r:true,d:'Display name (min 2 chars)'},{n:'password',t:'string',r:true,d:'Password (min 6 chars)'}],
            reqSample:'{\n  "email": "user@example.com",\n  "username": "johndoe",\n  "password": "securePass123"\n}',
            resSample:'{\n  "token": "eyJhbGci...jwt_token",\n  "user": {\n    "id": 1,\n    "email": "user@example.com",\n    "username": "johndoe",\n    "tier": "free",\n    "api_key": "ba_a1b2c3d4e5f6..."\n  }\n}',
            errors:[{c:400,d:'Email already registered or invalid input'}]},
          {tag:'Auth',m:'POST',p:'/auth/login',d:'Login with credentials',auth:'none',
            params:[{n:'email',t:'string',r:true,d:'Account email'},{n:'password',t:'string',r:true,d:'Account password'}],
            reqSample:'{\n  "email": "user@example.com",\n  "password": "securePass123"\n}',
            resSample:'{\n  "token": "eyJhbGci...jwt_token",\n  "user": {\n    "id": 1,\n    "email": "user@example.com",\n    "username": "johndoe",\n    "tier": "free"\n  }\n}',
            notes:'If 2FA is enabled, returns { "requires_2fa": true, "temp_token": "..." } instead. Use /auth/2fa/verify to complete login.',
            errors:[{c:401,d:'Invalid email or password'},{c:429,d:'Too many login attempts'}]},
          {tag:'Auth',m:'GET',p:'/auth/me',d:'Get current user profile',auth:'strict',
            resSample:'{\n  "id": 1,\n  "email": "user@example.com",\n  "username": "johndoe",\n  "tier": "free",\n  "api_key": "ba_a1b2c3...",\n  "totp_enabled": false,\n  "queries_today": 12,\n  "joined_at": "2026-03-01T00:00:00Z"\n}',
            errors:[{c:401,d:'Authentication required'}]},
          {tag:'Auth',m:'POST',p:'/auth/2fa/setup',d:'Initialize TOTP 2FA setup',auth:'strict',
            resSample:'{\n  "secret": "JBSWY3DPEHPK3PXP",\n  "uri": "otpauth://totp/BucketAudit:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=BucketAudit"\n}',
            notes:'Add the secret to an authenticator app, then confirm with /auth/2fa/confirm.',
            errors:[{c:401,d:'Authentication required'},{c:400,d:'2FA already enabled'}]},
          {tag:'Auth',m:'POST',p:'/auth/2fa/confirm',d:'Confirm 2FA with TOTP code',auth:'strict',
            params:[{n:'code',t:'string',r:true,d:'6-digit TOTP code from authenticator app'}],
            reqSample:'{ "code": "123456" }',
            resSample:'{\n  "success": true,\n  "backup_codes": ["abc12345", "def67890", "ghi13579", "jkl24680"]\n}',
            notes:'Save backup codes securely — they cannot be retrieved again.',
            errors:[{c:400,d:'Invalid TOTP code'},{c:401,d:'Authentication required'}]},
          {tag:'Auth',m:'POST',p:'/auth/2fa/verify',d:'Complete 2FA login',auth:'none',
            params:[{n:'temp_token',t:'string',r:true,d:'Temporary token from login response'},{n:'code',t:'string',r:true,d:'6-digit TOTP code or backup code'}],
            reqSample:'{\n  "temp_token": "temp_abc123...",\n  "code": "123456"\n}',
            resSample:'{\n  "token": "eyJhbGci...jwt_token",\n  "user": { "id": 1, "username": "johndoe" }\n}',
            errors:[{c:401,d:'Invalid or expired temp_token'},{c:401,d:'Invalid TOTP code'}]},
          {tag:'Auth',m:'POST',p:'/auth/rotate-key',d:'Generate new API key',auth:'strict',
            resSample:'{ "api_key": "ba_new_key_a1b2c3d4e5f6..." }',
            notes:'Old API key is immediately invalidated.',
            errors:[{c:401,d:'Authentication required'}]},
          {tag:'Files',m:'GET',p:'/files',d:'Full-text + regex file search',auth:'optional',
            params:[{n:'q',t:'string',r:false,d:'Search query (supports wildcards: *.env)'},{n:'regex',t:'string',r:false,d:'Regex pattern on file path'},{n:'ext',t:'string',r:false,d:'Filter by extension (e.g. sql, csv)'},{n:'exclude_ext',t:'string',r:false,d:'Exclude extension'},{n:'provider',t:'string',r:false,d:'aws | azure | gcp | digitalocean | alibaba'},{n:'bucket',t:'string',r:false,d:'Filter by bucket name'},{n:'sort',t:'string',r:false,d:'relevance | newest | oldest | largest | smallest'},{n:'min_size',t:'integer',r:false,d:'Minimum file size in bytes'},{n:'max_size',t:'integer',r:false,d:'Maximum file size in bytes'},{n:'date_from',t:'date',r:false,d:'Files modified after this date'},{n:'date_to',t:'date',r:false,d:'Files modified before this date'},{n:'page',t:'integer',r:false,d:'Page number (default: 1)'},{n:'per_page',t:'integer',r:false,d:'Results per page (default: 50, max: 200)'}],
            resSample:'{\n  "items": [\n    {\n      "id": 42,\n      "bucket_id": 5,\n      "name": "config/database.env",\n      "extension": "env",\n      "size": 1234,\n      "content_type": "text/plain",\n      "last_modified": "2026-03-15T10:30:00Z",\n      "ai_classification": "credentials",\n      "bucket_name": "company-backups",\n      "provider_name": "aws"\n    }\n  ],\n  "total": 156,\n  "page": 1,\n  "per_page": 50\n}',
            errors:[{c:429,d:'Rate limit exceeded (Free: 100/day, Premium: 5K, Enterprise: 50K)'}]},
          {tag:'Files',m:'GET',p:'/files/export',d:'Export search results as CSV or JSON',auth:'optional',
            params:[{n:'format',t:'string',r:true,d:'csv | json'},{n:'q',t:'string',r:false,d:'Search query'},{n:'ext',t:'string',r:false,d:'Extension filter'},{n:'provider',t:'string',r:false,d:'Provider filter'}],
            resSample:'# CSV format:\nid,name,extension,size,bucket,provider,url\n42,config/database.env,env,1234,company-backups,aws,https://...',
            notes:'Same search params as GET /files. CSV limited to 10,000 rows.',
            errors:[{c:429,d:'Rate limit exceeded'}]},
          {tag:'Files',m:'GET',p:'/files/:id/preview',d:'Preview file content (first 4KB)',auth:'optional',
            params:[{n:'file_id',t:'integer',r:true,d:'File ID (path param)'}],
            resSample:'{\n  "content": "DB_HOST=prod-db.example.com\\nDB_PASS=s3cret...",\n  "content_type": "text/plain",\n  "truncated": true\n}',
            notes:'Only works for text-based content types. Binary files return 400.',
            errors:[{c:404,d:'File not found'},{c:400,d:'Binary file, cannot preview'}]},
          {tag:'Buckets',m:'GET',p:'/buckets',d:'List cloud storage buckets',auth:'optional',
            params:[{n:'provider',t:'string',r:false,d:'aws | azure | gcp | digitalocean | alibaba'},{n:'status',t:'string',r:false,d:'open | closed | partial'},{n:'search',t:'string',r:false,d:'Search bucket names'},{n:'tag_id',t:'integer',r:false,d:'Filter by tag'},{n:'page',t:'integer',r:false,d:'Page number'},{n:'per_page',t:'integer',r:false,d:'Results per page (max: 200)'}],
            resSample:'{\n  "items": [\n    {\n      "id": 5,\n      "name": "company-backups",\n      "provider_name": "aws",\n      "region": "us-east-1",\n      "status": "open",\n      "file_count": 342,\n      "total_size_bytes": 52428800,\n      "risk_score": 85,\n      "risk_level": "critical",\n      "first_seen": "2026-03-01T00:00:00Z"\n    }\n  ],\n  "total": 1200,\n  "page": 1,\n  "per_page": 50\n}',
            errors:[{c:429,d:'Rate limit exceeded'}]},
          {tag:'Buckets',m:'GET',p:'/buckets/:id',d:'Get bucket details with files',auth:'optional',
            params:[{n:'bucket_id',t:'integer',r:true,d:'Bucket ID (path param)'},{n:'page',t:'integer',r:false,d:'File page'},{n:'per_page',t:'integer',r:false,d:'Files per page (default: 100)'}],
            resSample:'{\n  "id": 5,\n  "name": "company-backups",\n  "provider_name": "aws",\n  "region": "us-east-1",\n  "url": "https://company-backups.s3.amazonaws.com",\n  "status": "open",\n  "file_count": 342,\n  "risk_score": 85,\n  "risk_level": "critical",\n  "files": [\n    { "id": 42, "name": "database.env", "size": 1234 }\n  ],\n  "files_total": 342\n}',
            errors:[{c:404,d:'Bucket not found'}]},
          {tag:'Scans',m:'POST',p:'/scans',d:'Start a discovery scan',auth:'optional',
            params:[{n:'keywords',t:'array',r:false,d:'Bucket name keywords to try'},{n:'companies',t:'array',r:false,d:'Company names for pattern generation'},{n:'providers',t:'array',r:false,d:'Target providers (default: all)'},{n:'max_names',t:'integer',r:false,d:'Max name permutations (default: 1000, max: 50000)'},{n:'regions_per_provider',t:'integer',r:false,d:'Regions to check per provider (default: 3)'}],
            reqSample:'{\n  "keywords": ["backup", "staging", "dev"],\n  "companies": ["acme"],\n  "providers": ["aws", "gcp"],\n  "max_names": 500\n}',
            resSample:'{\n  "id": 15,\n  "scan_type": "discovery",\n  "status": "running",\n  "config": { "keywords": ["backup"], "providers": ["aws"] },\n  "created_at": "2026-03-22T10:00:00Z"\n}',
            notes:'Returns 202. Monitor via SSE at /events/scans or poll GET /scans/:id.',
            errors:[{c:400,d:'Invalid provider name'},{c:429,d:'Rate limit exceeded'}]},
          {tag:'Scans',m:'GET',p:'/scans',d:'List recent scan jobs',auth:'optional',
            resSample:'{\n  "items": [\n    {\n      "id": 15,\n      "status": "completed",\n      "names_checked": 500,\n      "buckets_found": 23,\n      "buckets_open": 5,\n      "files_indexed": 1842,\n      "created_at": "2026-03-22T10:00:00Z",\n      "completed_at": "2026-03-22T10:05:30Z"\n    }\n  ]\n}',
            notes:'Returns the 50 most recent scans.'},
          {tag:'Scans',m:'POST',p:'/scans/:id/cancel',d:'Cancel a running scan',auth:'optional',
            params:[{n:'job_id',t:'integer',r:true,d:'Scan job ID (path param)'}],
            resSample:'{ "success": true }',
            errors:[{c:404,d:'Scan job not found or not running'}]},
          {tag:'Scans',m:'GET',p:'/events/scans',d:'User-scoped real-time scan events (SSE)',auth:'bearer',
            resSample:'event: connected\ndata: {"msg":"connected"}\n\nevent: progress\ndata: {"names_checked":100,"names_total":500,"buckets_found":5,"buckets_open":2}\n\nevent: bucket_found\ndata: {"bucket":{"name":"staging-backup","provider":"aws","status":"open","file_count":42}}\n\nevent: scan_complete\ndata: {"job_id":15,"stats":{"buckets_found":23,"buckets_open":5}}',
            notes:'Server-Sent Events stream. Events: connected, progress, bucket_found, scan_started, scan_complete, scan_cancelled, drift_detected, error.'},
          {tag:'Monitoring',m:'POST',p:'/monitor/watchlists',d:'Create a watchlist for continuous monitoring',auth:'strict',
            params:[{n:'name',t:'string',r:true,d:'Watchlist name'},{n:'keywords',t:'array',r:true,d:'Keywords to monitor'},{n:'companies',t:'array',r:false,d:'Company names'},{n:'providers',t:'array',r:false,d:'Target providers'},{n:'scan_interval_hours',t:'integer',r:false,d:'Scan frequency in hours (default: 24)'}],
            reqSample:'{\n  "name": "Production Buckets",\n  "keywords": ["prod", "production"],\n  "companies": ["acme-corp"],\n  "scan_interval_hours": 12\n}',
            resSample:'{\n  "id": 3,\n  "name": "Production Buckets",\n  "keywords": ["prod", "production"],\n  "scan_interval_hours": 12,\n  "created_at": "2026-03-22T10:00:00Z"\n}',
            errors:[{c:400,d:'Name and keywords required'},{c:401,d:'Authentication required'}]},
          {tag:'Monitoring',m:'GET',p:'/monitor/alerts',d:'List monitoring alerts',auth:'strict',
            params:[{n:'unread',t:'boolean',r:false,d:'Filter unread only'},{n:'severity',t:'string',r:false,d:'critical | high | medium | low | info'},{n:'page',t:'integer',r:false,d:'Page number'},{n:'per_page',t:'integer',r:false,d:'Results per page'}],
            resSample:'{\n  "items": [\n    {\n      "id": 7,\n      "bucket_id": 5,\n      "severity": "critical",\n      "title": "New open bucket: company-backups",\n      "is_read": false,\n      "is_resolved": false,\n      "created_at": "2026-03-22T10:05:00Z"\n    }\n  ],\n  "total": 42,\n  "unread_count": 8\n}',
            errors:[{c:401,d:'Authentication required'}]},
          {tag:'Monitoring',m:'POST',p:'/monitor/webhooks',d:'Create a webhook for alert delivery',auth:'strict',
            params:[{n:'name',t:'string',r:true,d:'Webhook name'},{n:'url',t:'string',r:true,d:'Webhook URL (https)'},{n:'secret',t:'string',r:false,d:'HMAC signing secret'},{n:'event_types',t:'array',r:false,d:'Severity filter (default: ["critical","high"])'}],
            reqSample:'{\n  "name": "Slack Alerts",\n  "url": "https://hooks.slack.com/services/T.../B.../xxx",\n  "event_types": ["critical", "high", "medium"]\n}',
            resSample:'{ "id": 2, "name": "Slack Alerts", "is_active": true }',
            errors:[{c:400,d:'Name and URL required'},{c:401,d:'Authentication required'}]},
          {tag:'AI',m:'POST',p:'/ai/search',d:'Natural language search',auth:'optional',ai:true,
            params:[{n:'query',t:'string',r:true,d:'Natural language search query'}],
            reqSample:'{ "query": "find database backups from tech companies" }',
            resSample:'{\n  "interpretation": "Searching for database backup files from technology companies",\n  "search_params": { "q": "backup.sql OR dump.sql", "ext": "sql" },\n  "results": { "items": [...], "total": 23 }\n}',
            errors:[{c:400,d:'Query required'},{c:503,d:'AI provider unavailable'}]},
          {tag:'AI',m:'POST',p:'/ai/classify/:id',d:'Classify bucket files using AI',auth:'optional',ai:true,
            params:[{n:'bucket_id',t:'integer',r:true,d:'Bucket ID (path param)'}],
            resSample:'{\n  "classified": 42,\n  "classifications": [\n    { "file_id": 1, "classification": "credentials", "confidence": 0.95 },\n    { "file_id": 2, "classification": "pii", "confidence": 0.87 }\n  ]\n}',
            notes:'Classifications: credentials, pii, financial, medical, infrastructure, source_code, database, generic.',
            errors:[{c:404,d:'Bucket not found'},{c:503,d:'AI provider unavailable'}]},
          {tag:'AI',m:'POST',p:'/ai/risk/:id',d:'Calculate bucket risk score',auth:'optional',ai:true,
            params:[{n:'bucket_id',t:'integer',r:true,d:'Bucket ID (path param)'}],
            resSample:'{\n  "risk_score": 85,\n  "risk_level": "critical",\n  "factors": [\n    "Contains credentials files (.env, .pem)",\n    "Large number of exposed files (342)",\n    "PII detected in 12 files"\n  ]\n}',
            errors:[{c:404,d:'Bucket not found'},{c:503,d:'AI provider unavailable'}]},
          {tag:'AI',m:'POST',p:'/ai/report',d:'Generate AI security report',auth:'strict',ai:true,
            resSample:'{\n  "report": "## BucketAudit Security Report\\n\\n### Executive Summary\\n...",\n  "generated_at": "2026-03-22T10:00:00Z"\n}',
            errors:[{c:401,d:'Authentication required'},{c:503,d:'AI provider unavailable'}]},
          {tag:'Drift',m:'GET',p:'/drift/diffs',d:'List scan drift changes',auth:'strict',
            params:[{n:'severity',t:'string',r:false,d:'critical | high | medium | low | info'},{n:'unreviewed',t:'boolean',r:false,d:'Only unreviewed diffs'},{n:'page',t:'integer',r:false,d:'Page number'},{n:'per_page',t:'integer',r:false,d:'Results per page'}],
            resSample:'{\n  "items": [\n    {\n      "id": 1,\n      "bucket_id": 5,\n      "diff_type": "files_added",\n      "summary": "15 new files detected in company-backups",\n      "severity": "high",\n      "is_reviewed": false,\n      "created_at": "2026-03-22T10:05:00Z"\n    }\n  ],\n  "total": 8\n}',
            errors:[{c:401,d:'Authentication required'}]},
          {tag:'Drift',m:'GET',p:'/drift/diffs/summary',d:'Summary of all drift changes',auth:'optional',
            resSample:'{\n  "total": 24,\n  "unreviewed": 8,\n  "by_severity": { "critical": 2, "high": 5, "medium": 10, "low": 7 },\n  "by_type": { "files_added": 8, "status_change": 5, "new_bucket": 3 }\n}'},
          {tag:'Alert Rules',m:'POST',p:'/alert-rules',d:'Create custom alert rule',auth:'strict',
            params:[{n:'name',t:'string',r:true,d:'Rule name'},{n:'conditions',t:'array',r:true,d:'Array of {type, value} conditions (AND logic)'},{n:'severity',t:'string',r:false,d:'Rule severity (default: medium)'},{n:'description',t:'string',r:false,d:'Rule description'}],
            reqSample:'{\n  "name": "Credential files in open buckets",\n  "severity": "critical",\n  "conditions": [\n    { "type": "file_extension", "value": "env" },\n    { "type": "bucket_status", "value": "open" }\n  ]\n}',
            resSample:'{ "id": 3, "name": "Credential files in open buckets", "is_active": true }',
            notes:'Condition types: file_extension, file_size_gt, file_name_contains, bucket_name_contains, bucket_status, provider, file_count_gt, classification.',
            errors:[{c:400,d:'Name and conditions required'},{c:401,d:'Authentication required'}]},
          {tag:'Stats',m:'GET',p:'/stats',d:'Public platform statistics',auth:'none',
            resSample:'{\n  "total_buckets": 12500,\n  "total_files": 458000,\n  "total_size_bytes": 1073741824,\n  "providers": [\n    { "name": "aws", "bucket_count": 5200, "file_count": 180000 }\n  ],\n  "top_extensions": [\n    { "extension": "json", "count": 45000 }\n  ]\n}'},
          {tag:'Stats',m:'GET',p:'/dashboard/executive',d:'Executive dashboard with KPIs',auth:'optional',
            resSample:'{\n  "total_buckets": 12500,\n  "open_buckets": 3200,\n  "exposure_rate": 25.6,\n  "total_files": 458000,\n  "risk_distribution": { "critical": 120, "high": 450 },\n  "sensitive_files": { "credentials": 230, "pii": 180 },\n  "recent_scans": { "total": 15, "completed": 12 },\n  "top_exposed_buckets": [...]\n}'},
          {tag:'Compliance',m:'POST',p:'/compliance/check/:fid',d:'Run compliance check against framework',auth:'strict',
            params:[{n:'framework_id',t:'integer',r:true,d:'Framework ID (path param)'}],
            resSample:'{\n  "framework": "PCI-DSS",\n  "total_controls": 12,\n  "passed": 8,\n  "failed": 4,\n  "results": [\n    { "control_id": "PCI-3.4", "title": "Encrypt stored data", "status": "fail", "details": "12 unencrypted files found" }\n  ]\n}',
            errors:[{c:404,d:'Framework not found'},{c:401,d:'Authentication required'}]},
          {tag:'Remediations',m:'POST',p:'/remediations',d:'Create remediation task',auth:'strict',
            params:[{n:'bucket_id',t:'integer',r:true,d:'Bucket to remediate'},{n:'title',t:'string',r:true,d:'Task title'},{n:'description',t:'string',r:false,d:'Task description'},{n:'priority',t:'string',r:false,d:'critical | high | medium | low'},{n:'due_date',t:'date',r:false,d:'Due date'},{n:'assigned_to',t:'integer',r:false,d:'Assignee user ID'}],
            reqSample:'{\n  "bucket_id": 5,\n  "title": "Close exposed company-backups bucket",\n  "priority": "critical",\n  "due_date": "2026-03-29"\n}',
            resSample:'{ "id": 8, "status": "open", "created_at": "2026-03-22T10:00:00Z" }',
            errors:[{c:400,d:'bucket_id and title required'},{c:401,d:'Authentication required'}]},
          {tag:'Orgs',m:'POST',p:'/orgs',d:'Create organization',auth:'strict',
            params:[{n:'name',t:'string',r:true,d:'Organization name'},{n:'slug',t:'string',r:false,d:'URL-friendly slug'}],
            reqSample:'{ "name": "Acme Corp", "slug": "acme" }',
            resSample:'{ "id": 1, "name": "Acme Corp", "slug": "acme" }',
            errors:[{c:400,d:'Name required'},{c:401,d:'Authentication required'}]},
        ]
        const allTags=[...new Set(endpoints.map((e:any)=>e.tag))]
        const filtered=endpoints.filter((e:any)=>{
          if(apiFilterTag && e.tag!==apiFilterTag) return false
          if(apiSearchQ){const q=apiSearchQ.toLowerCase();return e.p.toLowerCase().includes(q)||e.d.toLowerCase().includes(q)||e.tag.toLowerCase().includes(q)} return true})
        return <div style={{padding:'80px 24px 24px',maxWidth:960,margin:'0 auto'}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8,flexWrap:'wrap',gap:12}}>
            <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',margin:0}}>REST API Reference</h2>
            <a href={`${API_BASE}/docs`} target="_blank" rel="noopener" style={{fontSize:12,color:'var(--accent)',textDecoration:'none',border:'1px solid var(--accent)',borderRadius:6,padding:'5px 12px'}}>Open Swagger UI →</a>
          </div>
          <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:20}}>Click any endpoint to view request, response, and error details. Auth: Bearer token, API key header, or query param.</p>
          <div className="card-static" style={{padding:12,marginBottom:20,display:'flex',gap:10,alignItems:'center',flexWrap:'wrap'}}>
            <div style={{flex:1,minWidth:180,display:'flex',alignItems:'center',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:6,overflow:'hidden'}}>
              <span style={{padding:'0 10px',color:'var(--text-muted)',fontSize:13}}>⌕</span>
              <input value={apiSearchQ} onChange={e=>setApiSearchQ(e.target.value)} placeholder="Filter endpoints..." style={{flex:1,background:'none',border:'none',color:'var(--text-primary)',fontSize:12,padding:'8px 8px 8px 0'}}/>
            </div>
            <div style={{display:'flex',gap:3,flexWrap:'wrap'}}>{['',  ...allTags].map(t=><button key={t||'all'} onClick={()=>setApiFilterTag(t)} style={{background:apiFilterTag===t?'var(--accent-bg)':'transparent',border:`1px solid ${apiFilterTag===t?'var(--accent)':'var(--border-subtle)'}`,color:apiFilterTag===t?'var(--accent)':'var(--text-tertiary)',borderRadius:5,padding:'3px 8px',fontSize:10,cursor:'pointer',fontWeight:apiFilterTag===t?600:400}}>{t||'All'}</button>)}</div>
          </div>
          <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:16}}>{filtered.length} endpoint{filtered.length!==1?'s':''}</div>
          {filtered.map((ep:any)=>{const key=ep.m+ep.p;const isOpen=expandedApi===key;const mc=MC[ep.m]||MC.GET;return <div key={key} style={{marginBottom:6}}>
            <div onClick={()=>setExpandedApi(isOpen?null:key)} style={{background:isOpen?'var(--bg-elevated)':'var(--bg-secondary)',border:`1px solid ${isOpen?'var(--border-strong)':ep.ai?'#a855f720':'var(--border-default)'}`,borderRadius:isOpen?'10px 10px 0 0':10,padding:'12px 16px',display:'flex',alignItems:'center',gap:10,cursor:'pointer',transition:'all 0.15s'}}>
              <span style={{background:mc.bg,color:mc.c,padding:'2px 8px',borderRadius:4,fontSize:10,fontWeight:700,border:`1px solid ${mc.bc}`,fontFamily:'var(--font-mono)',minWidth:52,textAlign:'center' as const}}>{ep.m}</span>
              <span style={{fontSize:13,fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-primary)'}}>{ep.p}</span>
              <span style={{fontSize:12,color:'var(--text-tertiary)',flex:1}}>{ep.d}</span>
              {ep.ai&&<span style={{background:'#a855f715',border:'1px solid #a855f730',color:'#a855f7',padding:'1px 6px',borderRadius:4,fontSize:9,fontWeight:600}}>AI</span>}
              <span style={{background:ep.auth==='strict'?'#f5a62315':ep.auth==='none'?'var(--accent-bg)':'#4a9eff15',color:ep.auth==='strict'?'var(--warning)':ep.auth==='none'?'var(--accent)':'var(--info)',padding:'1px 6px',borderRadius:4,fontSize:9,fontWeight:600,border:`1px solid ${ep.auth==='strict'?'rgba(245,166,35,0.2)':ep.auth==='none'?'rgba(0,232,123,0.2)':'rgba(74,158,255,0.2)'}`}}>{ep.auth==='strict'?'AUTH':'PUBLIC'}</span>
              <span style={{fontSize:10,color:'var(--text-muted)',transform:isOpen?'rotate(180deg)':'none',transition:'transform 0.2s'}}>▾</span>
            </div>
            {isOpen && <div style={{background:'var(--bg-secondary)',border:'1px solid var(--border-strong)',borderTop:'none',borderRadius:'0 0 10px 10px',padding:20,animation:'fadeIn 0.2s ease-out'}}>
              {ep.params&&ep.params.length>0&&<div style={{marginBottom:16}}>
                <div style={{fontSize:11,fontWeight:700,color:'var(--text-secondary)',textTransform:'uppercase' as const,letterSpacing:'0.5px',marginBottom:8}}>Parameters</div>
                <table style={{width:'100%',fontSize:12,borderCollapse:'collapse'}}>
                  <thead><tr style={{borderBottom:'1px solid var(--border-default)'}}>
                    <th style={{textAlign:'left',padding:'6px 8px',color:'var(--text-muted)',fontSize:10,fontWeight:600}}>Name</th>
                    <th style={{textAlign:'left',padding:'6px 8px',color:'var(--text-muted)',fontSize:10,fontWeight:600}}>Type</th>
                    <th style={{textAlign:'left',padding:'6px 8px',color:'var(--text-muted)',fontSize:10,fontWeight:600}}>Req</th>
                    <th style={{textAlign:'left',padding:'6px 8px',color:'var(--text-muted)',fontSize:10,fontWeight:600}}>Description</th>
                  </tr></thead>
                  <tbody>{ep.params.map((p:any)=><tr key={p.n} style={{borderBottom:'1px solid var(--border-subtle)'}}>
                    <td style={{padding:'6px 8px',fontFamily:'var(--font-mono)',color:'var(--accent-dim)',fontWeight:600}}>{p.n}</td>
                    <td style={{padding:'6px 8px',color:'var(--text-tertiary)'}}>{p.t}</td>
                    <td style={{padding:'6px 8px'}}>{p.r?<span style={{color:'var(--danger)',fontSize:10,fontWeight:700}}>required</span>:<span style={{color:'var(--text-muted)',fontSize:10}}>optional</span>}</td>
                    <td style={{padding:'6px 8px',color:'var(--text-secondary)'}}>{p.d}</td>
                  </tr>)}</tbody>
                </table>
              </div>}
              {ep.reqSample&&<div style={{marginBottom:16}}>
                <div style={{fontSize:11,fontWeight:700,color:'var(--text-secondary)',textTransform:'uppercase' as const,letterSpacing:'0.5px',marginBottom:8}}>Request Body</div>
                <pre style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:14,fontSize:12,fontFamily:'var(--font-mono)',color:'var(--accent-dim)',overflow:'auto',whiteSpace:'pre-wrap' as const,lineHeight:1.5}}>{ep.reqSample}</pre>
              </div>}
              <div style={{marginBottom:ep.errors||ep.notes?16:0}}>
                <div style={{fontSize:11,fontWeight:700,color:'var(--text-secondary)',textTransform:'uppercase' as const,letterSpacing:'0.5px',marginBottom:8}}>Response <span style={{color:'var(--accent)',fontWeight:400}}>200</span></div>
                <pre style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:14,fontSize:12,fontFamily:'var(--font-mono)',color:'var(--text-primary)',overflow:'auto',whiteSpace:'pre-wrap' as const,lineHeight:1.5}}>{ep.resSample}</pre>
              </div>
              {ep.notes&&<div style={{marginBottom:ep.errors?16:0,background:'#4a9eff08',border:'1px solid rgba(74,158,255,0.15)',borderRadius:8,padding:'10px 14px',fontSize:12,color:'var(--info)',lineHeight:1.5}}>
                <span style={{fontWeight:700}}>Note: </span>{ep.notes}
              </div>}
              {ep.errors&&ep.errors.length>0&&<div>
                <div style={{fontSize:11,fontWeight:700,color:'var(--text-secondary)',textTransform:'uppercase' as const,letterSpacing:'0.5px',marginBottom:8}}>Error Responses</div>
                {ep.errors.map((err:any,i:number)=><div key={i} style={{display:'flex',alignItems:'center',gap:10,padding:'6px 0',borderBottom:i<ep.errors.length-1?'1px solid var(--border-subtle)':'none'}}>
                  <span style={{background:'#f0484815',color:'#f04848',padding:'2px 8px',borderRadius:4,fontSize:11,fontWeight:700,fontFamily:'var(--font-mono)',border:'1px solid rgba(240,72,72,0.2)',minWidth:36,textAlign:'center' as const}}>{err.c}</span>
                  <span style={{fontSize:12,color:'var(--text-secondary)'}}>{err.d}</span>
                </div>)}
              </div>}
            </div>}
          </div>})}
        </div>})()}

      {/* ─── PRICING ─── */}
      {view==='pricing' && (()=>{
        const userTier = user?.tier || 'free'
        const plans = [
          { id:'free', name:'Free', price:'$0', period:'/forever', color:'var(--text-secondary)', desc:'Get started with cloud storage discovery', features:[
            ['API requests','100/day'],['Scans','3/day'],['Scan schedules','1'],['Keywords per scan','10'],['Providers','All 5'],['Search results','50/page'],['File preview','Basic'],['AI insights','—'],['Webhooks','—'],['Compliance','—'],['Organizations','—'],['Priority support','—'],
          ], limits:{scans:3,schedules:1,keywords:10,api:100} },
          { id:'premium', name:'Pro', price:'$29', period:'/month', color:'var(--accent)', desc:'For security professionals and small teams', popular:true, features:[
            ['API requests','5,000/day'],['Scans','50/day'],['Scan schedules','10'],['Keywords per scan','100'],['Providers','All 5'],['Search results','200/page'],['File preview','Full + download'],['AI insights','Included'],['Webhooks','5'],['Compliance','Basic'],['Organizations','1 (5 seats)'],['Priority support','Email'],
          ], limits:{scans:50,schedules:10,keywords:100,api:5000} },
          { id:'enterprise', name:'Enterprise', price:'$149', period:'/month', color:'#a855f7', desc:'Unlimited power for large security operations', features:[
            ['API requests','50,000/day'],['Scans','Unlimited'],['Scan schedules','Unlimited'],['Keywords per scan','Unlimited'],['Providers','All 5'],['Search results','Unlimited'],['File preview','Full + download + export'],['AI insights','Priority'],['Webhooks','Unlimited'],['Compliance','All frameworks'],['Organizations','Unlimited'],['Priority support','24/7 Slack + phone'],
          ], limits:{scans:-1,schedules:-1,keywords:-1,api:50000} },
        ]
        return <div style={{padding:'80px 24px 24px',maxWidth:1100,margin:'0 auto'}}>
          <div style={{textAlign:'center',marginBottom:48}}>
            <h2 style={{fontSize:28,fontWeight:800,fontFamily:'var(--font-display)',marginBottom:8,letterSpacing:'-0.03em'}}>Simple, Transparent Pricing</h2>
            <p style={{fontSize:14,color:'var(--text-secondary)',maxWidth:500,margin:'0 auto'}}>Choose the plan that fits your cloud security needs. Upgrade or downgrade anytime.</p>
          </div>

          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:20,marginBottom:48}}>
            {plans.map(plan=>{const isCurrent=userTier===plan.id;return <div key={plan.id} style={{background:'var(--bg-secondary)',border:plan.popular?`2px solid ${plan.color}`:'1px solid var(--border-default)',borderRadius:16,padding:0,position:'relative',overflow:'hidden',transition:'transform 0.2s,box-shadow 0.2s',boxShadow:plan.popular?`0 0 40px ${plan.color}15`:'var(--shadow-sm)'}}>
              {plan.popular && <div style={{background:`linear-gradient(135deg,${plan.color},#00c568)`,color:'#000',textAlign:'center',padding:'4px 0',fontSize:10,fontWeight:800,letterSpacing:'1px',textTransform:'uppercase' as const}}>MOST POPULAR</div>}
              <div style={{padding:'28px 24px 24px'}}>
                <div style={{fontSize:13,fontWeight:700,color:plan.color,textTransform:'uppercase' as const,letterSpacing:'0.5px',marginBottom:4}}>{plan.name}</div>
                <div style={{display:'flex',alignItems:'baseline',gap:4,marginBottom:8}}>
                  <span style={{fontSize:40,fontWeight:800,fontFamily:'var(--font-display)',letterSpacing:'-0.03em',color:'var(--text-primary)'}}>{plan.price}</span>
                  <span style={{fontSize:13,color:'var(--text-muted)'}}>{plan.period}</span>
                </div>
                <p style={{fontSize:12,color:'var(--text-secondary)',marginBottom:20,lineHeight:1.5}}>{plan.desc}</p>
                {isCurrent ? <div style={{background:plan.color+'18',border:`1px solid ${plan.color}40`,color:plan.color,textAlign:'center',padding:'10px 0',borderRadius:10,fontSize:13,fontWeight:700}}>Current Plan</div>
                : <button onClick={async()=>{if(!user){setAuthMode('login');setAuthError('');setView('auth');return};const r=await apiFetch('/auth/upgrade',{method:'POST',body:JSON.stringify({tier:plan.id})});if(r?.user){setUser(r.user);toast(`Upgraded to ${plan.name}!`,'success')}else{toast(r?.error||'Upgrade failed','error')}}} className="btn-primary" style={{width:'100%',padding:'10px 0',fontSize:13,borderRadius:10}}>
                  {!user?'Sign Up':userTier==='enterprise'?`Switch to ${plan.name}`:`Upgrade to ${plan.name}`}
                </button>}
                <div style={{marginTop:20,borderTop:'1px solid var(--border-subtle)',paddingTop:16}}>
                  {plan.features.map(([label,value]:string[],i:number)=><div key={i} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'6px 0',borderBottom:i<plan.features.length-1?'1px solid var(--border-subtle)':'none'}}>
                    <span style={{fontSize:12,color:'var(--text-secondary)'}}>{label}</span>
                    <span style={{fontSize:12,fontWeight:600,color:value==='—'?'var(--text-muted)':plan.color,fontFamily:value.match(/[0-9]/)?'var(--font-mono)':'inherit'}}>{value}</span>
                  </div>)}
                </div>
              </div>
            </div>})}
          </div>

          {/* Rate Limits Table */}
          <div className="card-static" style={{padding:28}}>
            <h3 style={{fontSize:17,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:4}}>Rate Limits &amp; Quotas</h3>
            <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:20}}>All limits reset daily at midnight UTC. Exceeding your limit returns HTTP 429.</p>
            <div style={{overflowX:'auto'}}>
              <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
                <thead><tr style={{borderBottom:'2px solid var(--border-default)'}}>
                  <th style={{textAlign:'left',padding:'10px 12px',color:'var(--text-muted)',fontSize:11,textTransform:'uppercase' as const,letterSpacing:'0.5px'}}>Resource</th>
                  <th style={{textAlign:'center',padding:'10px 12px',color:'var(--text-secondary)',fontSize:11}}>Free</th>
                  <th style={{textAlign:'center',padding:'10px 12px',color:'var(--accent)',fontSize:11}}>Pro</th>
                  <th style={{textAlign:'center',padding:'10px 12px',color:'#a855f7',fontSize:11}}>Enterprise</th>
                </tr></thead>
                <tbody>
                  {[
                    ['API Requests (per day)','100','5,000','50,000'],
                    ['Discovery Scans (per day)','3','50','Unlimited'],
                    ['Scan Schedules','1','10','Unlimited'],
                    ['Keywords per Scan','10','100','Unlimited'],
                    ['Max Concurrent Scans','1','3','10'],
                    ['Search Results per Page','50','200','Unlimited'],
                    ['File Preview','Basic','Full + Download','Full + Export'],
                    ['AI-Powered Insights','—','Included','Priority Queue'],
                    ['Webhook Integrations','—','5','Unlimited'],
                    ['Compliance Frameworks','—','Basic (SOC2)','All (SOC2, HIPAA, PCI, GDPR)'],
                    ['Organization & Team','—','1 org / 5 seats','Unlimited orgs & seats'],
                    ['Data Retention','30 days','1 year','Unlimited'],
                    ['Scan History','7 days','90 days','Unlimited'],
                    ['Export Formats','CSV','CSV, JSON','CSV, JSON, PDF, SARIF'],
                    ['Support','Community','Email','24/7 Slack + Phone'],
                  ].map(([resource,...vals],i)=><tr key={i} style={{borderBottom:'1px solid var(--border-subtle)',background:i%2===0?'var(--bg-primary)':'transparent'}}>
                    <td style={{padding:'10px 12px',fontWeight:500}}>{resource}</td>
                    {vals.map((v,j)=><td key={j} style={{textAlign:'center',padding:'10px 12px',color:v==='—'?'var(--text-muted)':j===0?'var(--text-secondary)':j===1?'var(--accent)':'#a855f7',fontWeight:v==='Unlimited'||v==='Priority Queue'?700:400,fontFamily:v.match(/^[0-9,]+$/)?'var(--font-mono)':'inherit'}}>{v}</td>)}
                  </tr>)}
                </tbody>
              </table>
            </div>
          </div>

          {/* FAQ */}
          <div style={{marginTop:40,marginBottom:40}}>
            <h3 style={{fontSize:17,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:20,textAlign:'center'}}>Frequently Asked Questions</h3>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
              {[
                ['How do rate limits work?','Each tier has a daily API request quota that resets at midnight UTC. Rate-limited requests receive HTTP 429 with a Retry-After header.'],
                ['Can I upgrade mid-cycle?','Yes! Upgrades take effect immediately. You only pay the prorated difference for the remainder of your billing period.'],
                ['What happens when I hit my scan limit?','You will receive a clear error message. Scheduled scans that exceed your limit are queued and run when your quota resets.'],
                ['Is there a free trial for Pro?','New accounts get a 14-day Pro trial with full access. No credit card required.'],
                ['Can I downgrade my plan?','Yes, you can downgrade at any time. The change takes effect at your next billing cycle. Your data is retained.'],
                ['Do you offer annual billing?','Yes! Annual plans save 20%. Contact us at bucketaudit@gmail.com for annual pricing.'],
              ].map(([q,a],i)=><div key={i} className="card-static" style={{padding:20}}>
                <div style={{fontSize:13,fontWeight:600,color:'var(--text-primary)',marginBottom:8}}>{q}</div>
                <div style={{fontSize:12,color:'var(--text-secondary)',lineHeight:1.6}}>{a}</div>
              </div>)}
            </div>
          </div>
        </div>
      })()}

      {/* ─── INTELLIGENCE HUB (Sprint 7 — 20 Features) ─── */}
      {view==='intelligence' && <div style={{padding:'80px 24px 24px',maxWidth:1200,margin:'0 auto'}}>
        <h2 style={{fontSize:22,fontWeight:700,fontFamily:'var(--font-display)',marginBottom:4}}>Intelligence Hub</h2>
        <p style={{fontSize:13,color:'var(--text-tertiary)',marginBottom:20}}>Advanced discovery, security analysis, compliance, and reporting across all 20 features.</p>

        {/* Feature Tabs */}
        <div style={{display:'flex',gap:4,flexWrap:'wrap',marginBottom:24,borderBottom:'1px solid var(--border-subtle)',paddingBottom:12}}>
          {[['overview','Overview'],['discovery','Discovery'],['sensitive','Sensitive Data'],['compliance-v','Compliance'],['exposure','Exposure'],['trends','Trends'],['surface','Attack Surface'],['industry','Industry'],['benchmark','Benchmark'],['tickets','Tickets'],['siem','SIEM Export'],['takedown','Takedown']].map(([id,label])=>
            <button key={id} onClick={()=>{setFeatView(id);if(id==='trends'&&!trendData)apiFetch('/trends?days=30').then(d=>d&&setTrendData(d))}} style={{padding:'6px 14px',borderRadius:6,border:featView===id?'1px solid var(--accent)':'1px solid var(--border-subtle)',background:featView===id?'var(--accent-bg)':'transparent',color:featView===id?'var(--accent)':'var(--text-secondary)',fontSize:11,fontWeight:featView===id?700:400,cursor:'pointer'}}>{label}</button>)}
        </div>

        {/* Overview */}
        {featView==='overview' && <div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:24}}>
            {[['🔍','Discovery','Subdomain enumeration, GitHub leak scanning, wildcard search, change detection'],
              ['🛡️','Security','Sensitive data classification, compliance mapping, exposure scoring, breach timeline'],
              ['📊','Intelligence','Industry breakdown, trend analytics, attack surface mapping, competitor benchmarks'],
              ['🔗','Integrations','Slack/Teams/Discord alerts, Jira tickets, SIEM export, API webhooks']
            ].map(([ic,title,desc])=><div key={title} className="card-static" style={{padding:20}}>
              <div style={{fontSize:28,marginBottom:8}}>{ic}</div>
              <div style={{fontSize:14,fontWeight:700,color:'var(--text-primary)',marginBottom:6}}>{title}</div>
              <div style={{fontSize:11,color:'var(--text-muted)',lineHeight:1.5}}>{desc}</div>
            </div>)}
          </div>
          <div className="card-static" style={{padding:20}}>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Quick Actions</h3>
            <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8}}>
              {[['Scan Sensitive Data','Run deep classification on all bucket files','sensitive',()=>{setFeatView('sensitive')}],
                ['View Compliance','Check compliance control violations','compliance-v',()=>{setFeatView('compliance-v');apiFetch('/compliance/violations').then(d=>d&&setCompViolations(d))}],
                ['Industry Breakdown','See exposure by industry sector','industry',()=>{setFeatView('industry');apiFetch('/industry/breakdown').then(d=>d?.industries&&setIndustryData(d.industries))}],
                ['Trend Analytics','View discovery trends over time','trends',()=>{setFeatView('trends');apiFetch('/trends?days=30').then(d=>d&&setTrendData(d))}],
                ['Attack Surface','Map your cloud attack surface','surface',()=>{setFeatView('surface');apiFetch('/attack-surface').then(d=>d&&setAttackSurface(d))}],
                ['Export SIEM','Export events for SIEM integration','siem',()=>{setFeatView('siem');apiFetch('/export/siem?format=json&hours=72').then(d=>d&&setSiemEvents(d.events||[]))}],
              ].map(([title,desc,id,action]:any)=>
                <button key={id} onClick={action} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:8,padding:12,cursor:'pointer',textAlign:'left'}}>
                  <div style={{fontSize:12,fontWeight:600,color:'var(--accent)',marginBottom:4}}>{title}</div>
                  <div style={{fontSize:10,color:'var(--text-muted)'}}>{desc}</div>
                </button>)}
            </div>
          </div>
        </div>}

        {/* Discovery */}
        {featView==='discovery' && <div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:24}}>
            {/* Subdomain Discovery */}
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Subdomain Discovery</h3>
              <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:12}}>Generate bucket names from domain/subdomain patterns.</p>
              <div style={{display:'flex',gap:8,marginBottom:12}}>
                <input value={subdomainDomain} onChange={e=>setSubdomainDomain(e.target.value)} placeholder="example.com" style={{...IS,flex:1}}/>
                <button onClick={()=>apiFetch('/discovery/subdomains',{method:'POST',body:JSON.stringify({domain:subdomainDomain})}).then(d=>d?.bucket_names&&setSubdomainNames(d.bucket_names))} className="btn-primary" style={{padding:'8px 16px',fontSize:11,whiteSpace:'nowrap'}}>Generate</button>
              </div>
              {subdomainNames.length>0 && <div style={{maxHeight:200,overflow:'auto',background:'var(--bg-primary)',borderRadius:6,padding:8}}>
                <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4}}>{subdomainNames.length} names generated</div>
                {subdomainNames.map((n,i)=><div key={i} style={{fontSize:11,color:'var(--accent-dim)',padding:'2px 0',fontFamily:'var(--font-mono)'}}>{n}</div>)}
              </div>}
            </div>

            {/* GitHub Leak Scanner */}
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Code Leak Scanner</h3>
              <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:12}}>Paste code to extract bucket references (S3 URLs, storage configs).</p>
              <textarea value={codeText} onChange={e=>setCodeText(e.target.value)} placeholder="Paste code, configs, or URLs here..." style={{...IS,height:80,resize:'vertical',fontFamily:'var(--font-mono)',fontSize:11}}/>
              <button onClick={()=>apiFetch('/discovery/extract-refs',{method:'POST',body:JSON.stringify({text:codeText})}).then(d=>d?.references&&setCodeRefs(d.references))} className="btn-primary" style={{marginTop:8,padding:'8px 16px',fontSize:11}}>Extract References</button>
              {codeRefs.length>0 && <div style={{marginTop:8,background:'var(--bg-primary)',borderRadius:6,padding:8}}>
                <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:4}}>{codeRefs.length} bucket references found</div>
                {codeRefs.map((r,i)=><div key={i} style={{fontSize:11,color:'var(--warning)',padding:'2px 0',fontFamily:'var(--font-mono)'}}>{r.name} <span style={{color:'var(--text-muted)',fontSize:9}}>({r.source})</span></div>)}
              </div>}
            </div>
          </div>

          {/* Wildcard Search */}
          <div className="card-static" style={{padding:20}}>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Wildcard Bucket Search</h3>
            <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:12}}>Search indexed buckets using patterns (* = any, ? = single char).</p>
            <div style={{display:'flex',gap:8,marginBottom:12}}>
              <input value={patternSearch} onChange={e=>setPatternSearch(e.target.value)} placeholder="*-backup-*, prod-*-data, *secret*" style={{...IS,flex:1,fontFamily:'var(--font-mono)'}}/>
              <button onClick={()=>apiFetch(`/buckets/search/pattern?pattern=${encodeURIComponent(patternSearch)}`).then(d=>d?.results&&setPatternResults(d.results))} className="btn-primary" style={{padding:'8px 16px',fontSize:11}}>Search</button>
            </div>
            {patternResults.length>0 && <div>
              <div style={{fontSize:10,color:'var(--text-muted)',marginBottom:8}}>{patternResults.length} matches</div>
              <div style={{display:'grid',gridTemplateColumns:'1fr 80px 80px 80px',gap:8,padding:'4px 8px',fontSize:10,color:'var(--text-muted)',fontWeight:600,borderBottom:'1px solid var(--border-subtle)'}}><span>Bucket</span><span>Status</span><span>Risk</span><span>Files</span></div>
              {patternResults.slice(0,20).map((b:any)=><div key={b.id} style={{display:'grid',gridTemplateColumns:'1fr 80px 80px 80px',gap:8,padding:'6px 8px',alignItems:'center',fontSize:12}}>
                <span style={{color:'var(--accent-dim)',fontWeight:600}}>{b.name}{b.company_name&&<span style={{color:'var(--info)',fontSize:10,marginLeft:6}}>{b.company_name}</span>}</span>
                <SBadge s={b.status}/>{b.risk_score!=null?<RiskBadge score={b.risk_score} level={b.risk_level||'info'}/>:<span style={{color:'var(--text-muted)'}}>—</span>}<span>{b.file_count||0}</span>
              </div>)}
            </div>}
          </div>
        </div>}

        {/* Sensitive Data */}
        {featView==='sensitive' && <div>
          <div style={{display:'flex',gap:8,marginBottom:16}}>
            <button onClick={()=>apiFetch('/sensitive/summary').then(d=>d&&setSensitiveSummary(d))} className="btn-primary" style={{padding:'8px 16px',fontSize:11}}>Load Summary</button>
            <button onClick={()=>apiFetch('/sensitive/findings?limit=100').then(d=>d&&setSensitiveFindings(d))} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',color:'var(--text-secondary)',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:11}}>All Findings</button>
          </div>

          {sensitiveSummary && <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:24}}>
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>By Severity</h3>
              {Object.entries(sensitiveSummary.by_severity||{}).map(([sev,count]:any)=><div key={sev} style={{display:'flex',justifyContent:'space-between',padding:'6px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                <SevBadge s={sev}/><span style={{fontSize:14,fontWeight:700}}>{count}</span></div>)}
            </div>
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>By Category</h3>
              {Object.entries(sensitiveSummary.by_category||{}).map(([cat,count]:any)=><div key={cat} style={{display:'flex',justifyContent:'space-between',padding:'6px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                <ClassBadge c={cat}/><span style={{fontSize:14,fontWeight:700}}>{count}</span></div>)}
            </div>
          </div>}

          {sensitiveFindings.findings?.length>0 && <div className="card-static" style={{padding:20}}>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Findings ({sensitiveFindings.count})</h3>
            {sensitiveFindings.findings.map((f:any,i:number)=><div key={i} style={{display:'flex',alignItems:'center',gap:12,padding:'8px 0',borderBottom:'1px solid var(--border-subtle)'}}>
              <SevBadge s={f.severity}/><ClassBadge c={f.category}/>
              <span style={{flex:1,fontSize:12,fontFamily:'var(--font-mono)',color:'var(--text-secondary)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{f.filepath}</span>
              <span style={{fontSize:11,color:'var(--text-muted)'}}>{f.bucket_name}</span>
            </div>)}
          </div>}
        </div>}

        {/* Compliance Violations */}
        {featView==='compliance-v' && <div>
          <button onClick={()=>apiFetch('/compliance/violations').then(d=>d&&setCompViolations(d))} className="btn-primary" style={{padding:'8px 16px',fontSize:11,marginBottom:16}}>Check Violations</button>

          {compViolations && <div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12,marginBottom:24}}>
              <div className="card-static" style={{padding:16,textAlign:'center'}}>
                <div style={{fontSize:28,fontWeight:800,color:'#f04848'}}>{compViolations.total_controls_violated}</div>
                <div style={{fontSize:11,color:'var(--text-muted)'}}>Controls Violated</div></div>
              <div className="card-static" style={{padding:16,textAlign:'center'}}>
                <div style={{fontSize:28,fontWeight:800,color:'var(--warning)'}}>{compViolations.frameworks_affected?.length||0}</div>
                <div style={{fontSize:11,color:'var(--text-muted)'}}>Frameworks Affected</div></div>
              <div className="card-static" style={{padding:16,textAlign:'center'}}>
                <div style={{fontSize:12,fontWeight:600,color:'var(--text-secondary)'}}>
                  {(compViolations.frameworks_affected||[]).map((f:string)=><span key={f} style={{display:'inline-block',margin:2,padding:'2px 8px',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:4,fontSize:10}}>{f}</span>)}
                </div>
                <div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>Affected Frameworks</div></div>
            </div>

            {compViolations.violations?.map((v:any)=><div key={v.control_id} className="card-static" style={{padding:16,marginBottom:8}}>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8}}>
                <div><span style={{fontSize:13,fontWeight:700}}>{v.control_id}</span><span style={{fontSize:11,color:'var(--text-muted)',marginLeft:8}}>{v.name}</span></div>
                <span style={{fontSize:12,fontWeight:700,color:'#f04848'}}>{v.finding_count} findings</span></div>
              <div style={{fontSize:11,color:'var(--text-tertiary)',marginBottom:8}}>{v.description}</div>
              <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
                {v.findings?.slice(0,5).map((f:any,i:number)=><span key={i} style={{fontSize:10,padding:'2px 6px',background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',borderRadius:4,fontFamily:'var(--font-mono)'}}>{f.filepath.split('/').pop()}</span>)}
              </div>
            </div>)}
          </div>}
        </div>}

        {/* Exposure Scoring */}
        {featView==='exposure' && <div className="card-static" style={{padding:20}}>
          <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Exposure Severity Scoring</h3>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:16}}>Click a bucket in the Buckets view to see its detailed exposure score. Scores factor in file types, volume, sensitivity findings, and access level.</p>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
            {[['File Types','.env, .pem, .key, .sql = Critical weight'],['Volume','10k+ files = +20, 1k+ = +15'],['Sensitive Data','Critical findings = +15 each, High = +10'],['Access Level','Open = +40, Partial = +20']].map(([t,d])=><div key={t} style={{padding:12,background:'var(--bg-primary)',borderRadius:8,border:'1px solid var(--border-subtle)'}}>
              <div style={{fontSize:12,fontWeight:700,marginBottom:4}}>{t}</div>
              <div style={{fontSize:11,color:'var(--text-muted)'}}>{d}</div></div>)}
          </div>
        </div>}

        {/* Trends */}
        {featView==='trends' && <div>
          <div style={{display:'flex',gap:8,marginBottom:20}}>
            {[7,30,90].map(d=><button key={d} onClick={()=>apiFetch(`/trends?days=${d}`).then(r=>r&&setTrendData(r))} className={trendData?.period_days===d?'btn-primary':''} style={{padding:'8px 16px',fontSize:11,background:trendData?.period_days===d?'':'var(--bg-secondary)',border:'1px solid var(--border-subtle)',borderRadius:8,color:trendData?.period_days===d?'#000':'var(--text-secondary)',cursor:'pointer',fontWeight:600}}>{d} days</button>)}
          </div>

          {/* Summary Stats Cards */}
          {trendData?.summary && <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:20}}>
            {[
              ['Total Buckets',fnum(trendData.summary.total_buckets),'var(--accent)',''],
              ['Open Buckets',fnum(trendData.summary.open_buckets),'#f04848',trendData.summary.total_buckets?`${Math.round((trendData.summary.open_buckets/trendData.summary.total_buckets)*100)}% exposure`:''],
              [`New (${trendData.period_days}d)`,fnum(trendData.period_stats?.new_buckets||0),'var(--info)',trendData.period_stats?.new_open?`${trendData.period_stats.new_open} open`:'all closed'],
              ['Companies Tracked',fnum(trendData.summary.unique_companies),'var(--warning)',''],
            ].map(([label,val,color,sub]:any)=><div key={label} className="card-static" style={{padding:16,textAlign:'center'}}>
              <div style={{fontSize:24,fontWeight:800,color,fontFamily:'var(--font-display)'}}>{val}</div>
              <div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>{label}</div>
              {sub&&<div style={{fontSize:10,color:'var(--text-tertiary)',marginTop:2}}>{sub}</div>}
            </div>)}
          </div>}

          {trendData && <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:20}}>
            {/* Buckets Chart */}
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:4}}>Buckets Discovered</h3>
              <p style={{fontSize:10,color:'var(--text-muted)',marginBottom:12}}>Daily discovery rate over {trendData.period_days} days. Red = has open buckets.</p>
              {trendData.bucket_trend?.length>0 ? <div>
                <div style={{display:'flex',alignItems:'end',gap:2,height:120}}>
                  {trendData.bucket_trend.map((d:any,i:number)=>{const max=Math.max(...trendData.bucket_trend.map((x:any)=>x.discovered||0),1);return <div key={i} style={{flex:1,background:d.open>0?'#f04848':'var(--accent)',height:`${Math.max(4,(d.discovered/max)*100)}%`,borderRadius:'2px 2px 0 0',minHeight:4,transition:'height 0.3s'}} title={`${d.date}: ${d.discovered} found, ${d.open} open`}/>})}
                </div>
                <div style={{display:'flex',justifyContent:'space-between',marginTop:6,fontSize:9,color:'var(--text-muted)'}}>
                  <span>{trendData.bucket_trend[0]?.date}</span>
                  <span>{trendData.bucket_trend[trendData.bucket_trend.length-1]?.date}</span>
                </div>
                <div style={{display:'flex',gap:12,marginTop:8,fontSize:10,color:'var(--text-muted)'}}>
                  <span><span style={{display:'inline-block',width:8,height:8,borderRadius:2,background:'var(--accent)',marginRight:4}}/>Closed</span>
                  <span><span style={{display:'inline-block',width:8,height:8,borderRadius:2,background:'#f04848',marginRight:4}}/>Has Open</span>
                </div>
              </div> : <div style={{color:'var(--text-muted)',fontSize:12,padding:20,textAlign:'center'}}>No bucket data for this period</div>}
            </div>
            {/* Files Chart */}
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:4}}>Files Indexed</h3>
              <p style={{fontSize:10,color:'var(--text-muted)',marginBottom:12}}>Daily file indexing volume. Total: {fnum(trendData.summary?.total_files||0)} files ({fmt(trendData.summary?.total_size||0)})</p>
              {trendData.file_trend?.length>0 ? <div>
                <div style={{display:'flex',alignItems:'end',gap:2,height:120}}>
                  {trendData.file_trend.map((d:any,i:number)=>{const max=Math.max(...trendData.file_trend.map((x:any)=>x.indexed||0),1);return <div key={i} style={{flex:1,background:'var(--info)',height:`${Math.max(4,(d.indexed/max)*100)}%`,borderRadius:'2px 2px 0 0',minHeight:4,transition:'height 0.3s'}} title={`${d.date}: ${d.indexed} files (${fmt(d.total_size)})`}/>})}
                </div>
                <div style={{display:'flex',justifyContent:'space-between',marginTop:6,fontSize:9,color:'var(--text-muted)'}}>
                  <span>{trendData.file_trend[0]?.date}</span>
                  <span>{trendData.file_trend[trendData.file_trend.length-1]?.date}</span>
                </div>
              </div> : <div style={{color:'var(--text-muted)',fontSize:12,padding:20,textAlign:'center'}}>No file data for this period</div>}
            </div>
          </div>}

          {/* Provider Breakdown + Top Regions */}
          {trendData && <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Provider Breakdown</h3>
              {trendData.provider_breakdown?.length>0 ? trendData.provider_breakdown.map((p:any)=>{const pct=trendData.summary?.total_buckets?Math.round((p.count/trendData.summary.total_buckets)*100):0;return <div key={p.provider} style={{marginBottom:10}}>
                <div style={{display:'flex',justifyContent:'space-between',fontSize:12,marginBottom:4}}>
                  <span style={{fontWeight:600}}>{PL[p.provider]||p.provider}</span>
                  <span style={{color:'var(--text-muted)'}}>{fnum(p.count)} ({pct}%){p.open>0&&<span style={{color:'#f04848',marginLeft:6}}>{p.open} open</span>}</span>
                </div>
                <div style={{height:6,background:'var(--bg-primary)',borderRadius:3,overflow:'hidden'}}>
                  <div style={{height:'100%',width:`${pct}%`,background:p.open>0?'linear-gradient(90deg, var(--accent), #f04848)':'var(--accent)',borderRadius:3,transition:'width 0.5s'}}/>
                </div>
              </div>}) : <div style={{color:'var(--text-muted)',fontSize:12}}>No provider data</div>}
            </div>
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Top Regions</h3>
              {trendData.top_regions?.length>0 ? trendData.top_regions.map((r:any,i:number)=>{const max=Math.max(...trendData.top_regions.map((x:any)=>x.count),1);return <div key={r.region} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                <span style={{fontSize:10,color:'var(--text-muted)',width:16,textAlign:'right'}}>{i+1}</span>
                <div style={{flex:1}}>
                  <div style={{display:'flex',justifyContent:'space-between',fontSize:11,marginBottom:2}}>
                    <span style={{fontWeight:500}}>{r.region}</span>
                    <span style={{color:'var(--text-muted)'}}>{fnum(r.count)}{r.open>0&&<span style={{color:'#f04848',marginLeft:4}}>({r.open} open)</span>}</span>
                  </div>
                  <div style={{height:4,background:'var(--bg-primary)',borderRadius:2,overflow:'hidden'}}>
                    <div style={{height:'100%',width:`${(r.count/max)*100}%`,background:'var(--info)',borderRadius:2}}/>
                  </div>
                </div>
              </div>}) : <div style={{color:'var(--text-muted)',fontSize:12}}>No region data</div>}
            </div>
          </div>}

          {/* Status Changes */}
          {trendData?.status_changes?.length>0 && <div className="card-static" style={{padding:20,marginTop:16}}>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Status Changes ({trendData.period_days}d)</h3>
            <div style={{display:'flex',gap:16,flexWrap:'wrap'}}>
              {Object.entries(trendData.status_changes.reduce((a:any,c:any)=>{a[c.type]=(a[c.type]||0)+c.count;return a},{})).map(([type,count]:any)=><div key={type} style={{padding:'8px 16px',background:'var(--bg-primary)',borderRadius:8,textAlign:'center'}}>
                <div style={{fontSize:18,fontWeight:700,color:type==='new_open'?'#f04848':type==='closed'?'var(--accent)':'var(--info)'}}>{fnum(count)}</div>
                <div style={{fontSize:10,color:'var(--text-muted)',marginTop:2}}>{type.replace(/_/g,' ')}</div>
              </div>)}
            </div>
          </div>}
        </div>}

        {/* Attack Surface */}
        {featView==='surface' && <div>
          <div style={{display:'flex',gap:8,marginBottom:16}}>
            <button onClick={()=>apiFetch('/attack-surface').then(d=>d&&setAttackSurface(d))} className="btn-primary" style={{padding:'8px 16px',fontSize:11}}>Map All</button>
          </div>
          {attackSurface?.summary && <div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:16}}>
              {[['Buckets',attackSurface.summary.total_buckets],['Files',fnum(attackSurface.summary.total_files)],['Data',fmt(attackSurface.summary.total_size_bytes)],['Regions',Object.keys(attackSurface.summary.regions||{}).length]].map(([l,v]:any)=>
                <div key={l} className="card-static" style={{padding:12,textAlign:'center'}}><div style={{fontSize:22,fontWeight:800}}>{v}</div><div style={{fontSize:10,color:'var(--text-muted)'}}>{l}</div></div>)}
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:16}}>
              <div className="card-static" style={{padding:16}}>
                <h4 style={{fontSize:12,fontWeight:700,marginBottom:8}}>By Provider</h4>
                {Object.entries(attackSurface.summary.providers||{}).map(([p,c]:any)=><div key={p} style={{display:'flex',justifyContent:'space-between',padding:'4px 0'}}><Badge provider={p}/><span style={{fontWeight:700}}>{c}</span></div>)}
              </div>
              <div className="card-static" style={{padding:16}}>
                <h4 style={{fontSize:12,fontWeight:700,marginBottom:8}}>By Status</h4>
                {Object.entries(attackSurface.summary.statuses||{}).filter(([,c]:any)=>c>0).map(([s,c]:any)=><div key={s} style={{display:'flex',justifyContent:'space-between',padding:'4px 0'}}><SBadge s={s}/><span style={{fontWeight:700}}>{c}</span></div>)}
              </div>
            </div>
            <div className="card-static" style={{padding:16}}>
              <h4 style={{fontSize:12,fontWeight:700,marginBottom:8}}>Top Risk Nodes ({attackSurface.nodes?.length})</h4>
              {attackSurface.nodes?.slice(0,15).map((n:any)=><div key={n.id} style={{display:'flex',alignItems:'center',gap:8,padding:'4px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                <span style={{fontSize:12,fontWeight:600,color:'var(--accent-dim)',flex:1}}>{n.name}</span>
                {n.company_name&&<span style={{fontSize:10,color:'var(--info)'}}>{n.company_name}</span>}
                <Badge provider={n.provider}/><SBadge s={n.status}/>
                {n.risk_score!=null&&<RiskBadge score={n.risk_score} level={n.risk_level||'info'}/>}
              </div>)}
            </div>
          </div>}
        </div>}

        {/* Industry */}
        {featView==='industry' && <div>
          <button onClick={()=>apiFetch('/industry/breakdown').then(d=>d?.industries&&setIndustryData(d.industries))} className="btn-primary" style={{padding:'8px 16px',fontSize:11,marginBottom:16}}>Load Industry Data</button>
          {industryData.length>0 && <div className="card-static" style={{padding:20}}>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Exposure by Industry</h3>
            {industryData.map((ind:any)=><div key={ind.industry} style={{display:'flex',alignItems:'center',gap:12,padding:'10px 0',borderBottom:'1px solid var(--border-subtle)'}}>
              <span style={{width:120,fontSize:12,fontWeight:700,textTransform:'capitalize'}}>{ind.industry}</span>
              <div style={{flex:1,height:8,background:'var(--bg-primary)',borderRadius:4,overflow:'hidden'}}>
                <div style={{height:'100%',background:ind.open_buckets>0?'#f04848':'var(--accent)',borderRadius:4,width:`${Math.min(100,(ind.buckets/Math.max(...industryData.map((x:any)=>x.buckets),1))*100)}%`}}/>
              </div>
              <span style={{width:60,fontSize:12,fontWeight:600,textAlign:'right'}}>{ind.buckets} buckets</span>
              <span style={{width:50,fontSize:10,color:ind.open_buckets>0?'#f04848':'var(--text-muted)'}}>{ind.open_buckets} open</span>
              <span style={{width:60,fontSize:10,color:'var(--text-muted)'}}>{ind.companies} co.</span>
            </div>)}
          </div>}
        </div>}

        {/* Benchmark */}
        {featView==='benchmark' && <div>
          <div style={{display:'flex',gap:8,marginBottom:16}}>
            <input value={benchmarkCompany} onChange={e=>setBenchmarkCompany(e.target.value)} placeholder="Company name" style={{...IS,width:300}}/>
            <button onClick={()=>apiFetch(`/benchmark?company=${encodeURIComponent(benchmarkCompany)}`).then(d=>d&&setBenchmarkData(d))} className="btn-primary" style={{padding:'8px 16px',fontSize:11}}>Compare</button>
          </div>
          {benchmarkData?.benchmark && <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>{benchmarkData.company}</h3>
              <div style={{fontSize:11,color:'var(--info)',marginBottom:12}}>Industry: {benchmarkData.industry}</div>
              {Object.entries(benchmarkData.stats||{}).map(([k,v]:any)=><div key={k} style={{display:'flex',justifyContent:'space-between',padding:'6px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                <span style={{fontSize:12,color:'var(--text-muted)'}}>{k.replace(/_/g,' ')}</span><span style={{fontSize:12,fontWeight:700}}>{typeof v==='number'?v.toLocaleString():v}</span></div>)}
            </div>
            <div className="card-static" style={{padding:20}}>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Industry Benchmark</h3>
              {Object.entries(benchmarkData.benchmark||{}).map(([k,v]:any)=><div key={k} style={{display:'flex',justifyContent:'space-between',padding:'6px 0',borderBottom:'1px solid var(--border-subtle)'}}>
                <span style={{fontSize:12,color:'var(--text-muted)'}}>{k.replace(/_/g,' ')}</span><span style={{fontSize:12,fontWeight:700}}>{typeof v==='number'?v.toLocaleString():v}</span></div>)}
            </div>
          </div>}
        </div>}

        {/* Tickets */}
        {featView==='tickets' && <div>
          <button onClick={()=>apiFetch('/tickets').then(d=>d?.tickets&&setTickets(d.tickets))} className="btn-primary" style={{padding:'8px 16px',fontSize:11,marginBottom:16}}>Load Tickets</button>
          {tickets.length>0 ? tickets.map((t:any)=><div key={t.id} className="card-static" style={{padding:16,marginBottom:8}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
              <div><span style={{fontSize:13,fontWeight:700}}>{t.title}</span><span style={{fontSize:10,color:'var(--text-muted)',marginLeft:8}}>{t.platform}</span></div>
              <SevBadge s={t.priority}/>
            </div>
            {t.description&&<div style={{fontSize:11,color:'var(--text-tertiary)',marginTop:4}}>{t.description}</div>}
            <div style={{fontSize:10,color:'var(--text-muted)',marginTop:4}}>Status: {t.status} • {t.bucket_name&&`Bucket: ${t.bucket_name} • `}{ago(t.created_at)}</div>
          </div>) : <div style={{color:'var(--text-muted)',fontSize:12}}>No tickets created yet. Create tickets from alerts or bucket findings.</div>}
        </div>}

        {/* SIEM Export */}
        {featView==='siem' && <div>
          <div style={{display:'flex',gap:8,marginBottom:16}}>
            <button onClick={()=>apiFetch('/export/siem?format=json&hours=72').then(d=>d&&setSiemEvents(d.events||[]))} className="btn-primary" style={{padding:'8px 16px',fontSize:11}}>Export JSON (72h)</button>
            <button onClick={()=>apiFetch('/export/siem?format=cef&hours=72').then(d=>d&&setSiemEvents(d.events||[]))} style={{background:'var(--bg-secondary)',border:'1px solid var(--border-subtle)',color:'var(--text-secondary)',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:11}}>Export CEF</button>
          </div>
          <div className="card-static" style={{padding:20}}>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Events ({siemEvents.length})</h3>
            <div style={{maxHeight:400,overflow:'auto',background:'var(--bg-primary)',borderRadius:8,padding:12,fontFamily:'var(--font-mono)',fontSize:11}}>
              {siemEvents.length>0 ? siemEvents.map((e:any,i:number)=><div key={i} style={{padding:'4px 0',borderBottom:'1px solid var(--border-subtle)',wordBreak:'break-all'}}>{typeof e==='string'?e:JSON.stringify(e)}</div>)
              : <div style={{color:'var(--text-muted)'}}>No events in the selected time period.</div>}
            </div>
          </div>
        </div>}

        {/* Takedown */}
        {featView==='takedown' && <div className="card-static" style={{padding:20}}>
          <h3 style={{fontSize:14,fontWeight:700,marginBottom:12}}>Takedown Assistance</h3>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:16}}>Get responsible disclosure guides from the bucket detail view. Click any bucket, then use the "Takedown Guide" button.</p>
          <h4 style={{fontSize:12,fontWeight:700,marginBottom:8}}>Provider Abuse Contacts</h4>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
            {[['AWS','abuse@amazonaws.com','https://support.aws.amazon.com/#/contacts/report-abuse'],
              ['Azure','cert@microsoft.com','https://msrc.microsoft.com/report/abuse'],
              ['GCP','gcp-abuse@google.com','https://support.google.com/code/contact/cloud_platform_report'],
              ['DigitalOcean','abuse@digitalocean.com','https://www.digitalocean.com/company/contact#abuse'],
              ['Alibaba','abuse@service.alibaba.com','https://www.alibabacloud.com/report'],
            ].map(([name,email,url])=><div key={name} style={{padding:12,background:'var(--bg-primary)',borderRadius:8,border:'1px solid var(--border-subtle)'}}>
              <div style={{fontSize:12,fontWeight:700,marginBottom:4}}>{name}</div>
              <div style={{fontSize:10,color:'var(--info)',marginBottom:2}}>{email}</div>
              <div style={{fontSize:10,color:'var(--text-muted)',wordBreak:'break-all'}}>{url}</div>
            </div>)}
          </div>
        </div>}
      </div>}

      {/* ─── TOAST NOTIFICATIONS ─── */}
      {toasts.length>0 && <div style={{position:'fixed',bottom:20,right:20,zIndex:9999,display:'flex',flexDirection:'column',gap:8}}>
        {toasts.map(t=><div key={t.id} className="toast" style={{padding:'12px 20px',borderRadius:10,fontSize:13,fontWeight:600,fontFamily:'var(--font-body)',boxShadow:'var(--shadow-lg)',border:'1px solid',minWidth:280,
          ...(t.type==='success'?{background:'rgba(0,232,123,0.15)',borderColor:'rgba(0,232,123,0.3)',color:'var(--accent)'}:
             t.type==='error'?{background:'rgba(240,72,72,0.15)',borderColor:'rgba(240,72,72,0.3)',color:'#f04848'}:
             {background:'rgba(74,158,255,0.15)',borderColor:'rgba(74,158,255,0.3)',color:'#4a9eff'})
        }}>{t.type==='success'?'✓ ':t.type==='error'?'✕ ':'ℹ '}{t.msg}</div>)}
      </div>}

      {/* ─── CONFIRMATION MODAL ─── */}
      {modal && <div onClick={()=>setModal(null)} style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.6)',backdropFilter:'blur(4px)',zIndex:9998,display:'flex',alignItems:'center',justifyContent:'center'}}>
        <div onClick={e=>e.stopPropagation()} className="card-static fade-in" style={{padding:24,width:400,maxWidth:'90vw'}}>
          <h3 style={{fontSize:16,fontWeight:700,marginBottom:8}}>{modal.title}</h3>
          <p style={{fontSize:13,color:'var(--text-secondary)',marginBottom:16}}>{modal.msg}</p>
          {modal.input && <input autoFocus value={modalInput} onChange={e=>setModalInput(e.target.value)} style={{...IS,marginBottom:16}} onKeyDown={e=>{if(e.key==='Enter'){modal.onConfirm();setModal(null)}}}/>}
          <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
            <button onClick={()=>setModal(null)} style={{background:'var(--bg-primary)',border:'1px solid var(--border-subtle)',color:'var(--text-secondary)',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:12}}>Cancel</button>
            <button onClick={()=>{modal.onConfirm();setModal(null)}} style={{background:'var(--accent)',border:'none',color:'#000',padding:'8px 16px',borderRadius:8,cursor:'pointer',fontSize:12,fontWeight:600}}>Confirm</button>
          </div>
        </div>
      </div>}
    </div>
  )
}
