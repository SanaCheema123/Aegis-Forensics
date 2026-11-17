import { useState, type ReactNode } from 'react'
import { NavLink, useLocation, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, LayoutDashboard, ScanLine, Fingerprint, Database, BrainCircuit, ShieldAlert, Radio, Clock3, FileText, ChartNoAxesCombined, ListChecks, Settings, PanelLeftClose, Menu, Sun, Moon, Bell, ChevronRight, CircleHelp } from 'lucide-react'
import { useWorkspace } from '../../app/context'
import { api } from '../../services/api'
import { Button } from '../ui/button'
import { Badge, Drawer, Empty, ErrorState } from '../common'
import { date } from '../../lib/utils'

export const navigation = [
  ['/', 'Dashboard', LayoutDashboard], ['/scanner', 'Security Scanner', ScanLine], ['/investigations', 'Investigations', Fingerprint],
  ['/evidence', 'Evidence Vault', Database], ['/anomalies', 'AI Anomaly Detection', BrainCircuit], ['/rules', 'Threat Rules', ShieldAlert],
  ['/monitoring', 'Live Protection', Radio], ['/timeline', 'Timeline', Clock3], ['/reports', 'Forensic Reports', FileText],
  ['/evaluation', 'Model Evaluation', ChartNoAxesCombined], ['/audit', 'Audit Integrity', ListChecks], ['/settings', 'Settings', Settings],
] as const

export function Shell({ children }: {children: ReactNode}) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobile,setMobile] = useState(false)
  const [theme,setTheme] = useState(localStorage.getItem('aegis.theme') || 'dark')
  const {caseId,setCaseId,cases,error} = useWorkspace()
  const location = useLocation()
  const title = navigation.find(([path])=>path===location.pathname)?.[1] || 'Page not found'
  const monitor = useQuery({queryKey:['monitoring'],queryFn:()=>api('/monitoring'),refetchInterval:15000,retry:1})
  const changeTheme = () => { const next=theme==='dark'?'light':'dark'; setTheme(next); localStorage.setItem('aegis.theme',next); document.documentElement.dataset.theme=next }
  return <div className={'application '+(collapsed?'collapsed ':'')+(mobile?'mobile-open':'')}>
    {mobile&&<button className="mobile-overlay" aria-label="Close navigation" onClick={()=>setMobile(false)}/>}
    <aside className="sidebar"><Link to="/" className="brand"><div className="brand-icon"><ShieldCheck size={27}/></div><div className="brand-text"><strong>AEGIS<span> FORENSICS</span></strong><small>INVESTIGATE WITH CONFIDENCE</small></div></Link>
      <div className="workspace-label">WORKSPACE <span>LOCAL</span></div>
      <nav aria-label="Main navigation">{navigation.map(([path,label,Icon],index)=><NavLink title={label} key={path} to={path} end={path==='/'} onClick={()=>setMobile(false)} className={({isActive})=>(isActive?'active ':'')+(index===8?'nav-section':'')}><Icon size={19}/><span>{label}</span>{label==='Live Protection'&&monitor.data?.status?.running&&<i className="status-dot"/>}</NavLink>)}</nav>
      <div className="sidebar-footer"><ShieldCheck size={17}/><div><strong>Evidence-led analysis</strong><small>Local operator workspace</small></div><button aria-label="Collapse sidebar" onClick={()=>setCollapsed(!collapsed)}><PanelLeftClose size={17}/></button></div>
    </aside>
    <div className="main-column"><header className="topbar"><div className="breadcrumbs"><Button variant="ghost" className="mobile-menu" aria-label="Open navigation" onClick={()=>setMobile(true)}><Menu size={20}/></Button><span>Workspace</span><ChevronRight size={13}/><strong>{title}</strong></div><div className="top-actions"><label className="case-select"><span>CASE</span><select aria-label="Current case" value={caseId} onChange={e=>setCaseId(e.target.value)}>{!cases.length&&<option value="">No cases</option>}{cases.map(c=><option key={c.case_id} value={c.case_id}>{c.case_id}{c.verified?'':' · verification failed'}</option>)}</select></label><div className="monitor-indicator"><i className={'status-dot '+(monitor.data?.status?.running?'':'inactive')}/><span>{monitor.error?'Status unavailable':monitor.data?.status?.running?'Monitoring active':'Monitor stopped'}</span></div><span className="top-divider"/>
      <Button variant="ghost" aria-label="Toggle theme" onClick={changeTheme}>{theme==='dark'?<Sun size={19}/>:<Moon size={19}/>}</Button>
      <Drawer title="Recorded notifications" trigger={<Button variant="ghost" aria-label="Open notifications"><Bell size={19}/></Button>}>{monitor.error?<ErrorState error={monitor.error}/>:monitor.data?.alerts?.length?monitor.data.alerts.map((a:any,i:number)=><div className="activity-item" key={i}><span>{a.message || a.description || 'Recorded monitor observation'}</span><small>{date(a.created_at_utc)}</small></div>):<Empty title="No recorded monitor alerts"/>}</Drawer><Link className="icon-link" aria-label="Settings" to="/settings"><Settings size={19}/></Link></div></header>
      <main>{error&&<ErrorState error={error}/ >}{children}</main><footer className="app-footer"><span><ShieldCheck size={13}/> Aegis Forensics · Local investigation console</span><span><CircleHelp size={13}/> Findings are investigative indicators</span></footer></div>
  </div>
}
