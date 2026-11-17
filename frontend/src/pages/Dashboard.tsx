import { lazy, Suspense } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowUpRight, ArrowRight, BriefcaseBusiness, Database, Flag, ShieldAlert, ShieldCheck, Radio, ScanLine, Fingerprint, Activity } from 'lucide-react'
import { api } from '../services/api'
import { useWorkspace } from '../app/context'
import { Card, PageHeading, ErrorState, Loading, Empty, Badge, Notice } from '../components/common'
import { date } from '../lib/utils'
const Chart=lazy(()=>import('../components/charts/FindingsChart'))
export default function Dashboard() {
  const {caseId,setCaseId}=useWorkspace()
  const result=useQuery({queryKey:['dashboard',caseId],queryFn:()=>api('/dashboard?case_id='+encodeURIComponent(caseId)),enabled:!!caseId})
  const monitor=useQuery({queryKey:['monitoring'],queryFn:()=>api('/monitoring'),refetchInterval:15000})
  const data=result.data
  return <><PageHeading eyebrow="SECURITY OPERATIONS / OVERVIEW" title="Investigation overview" description="A clear view of your evidence, findings, and investigation activity." action={<Link className="button button-primary" to="/scanner"><ScanLine size={17}/> New scan <ArrowUpRight size={16}/></Link>}/>
    <div className="scope-strip"><div><i className="status-dot"/><strong>{caseId||'No case selected'}</strong><span>Verified histories · local workspace</span></div><Badge tone="low">EVIDENCE FIRST</Badge></div>
    {result.isLoading?<Loading/>:result.error?<ErrorState error={result.error}/>:!data?<Empty title="Start with a case"><Link to="/investigations">Create your first case</Link></Empty>:<>
    {data.invalid_cases.length>0&&<Notice>This case's audit chain failed verification. Its evidence and findings are excluded. <Link to="/audit">Inspect verification</Link></Notice>}
    <div className="kpi-grid">{[
      ['Total cases',data.total_cases,BriefcaseBusiness,'Recorded case histories'],['Saved evidence',data.saved_evidence,Database,'In selected verified case'],['Verified evidence',data.verified_evidence??'—',ShieldCheck,'Current source hash checks'],['Pending reviews',data.open_reviews,Flag,'Flags for investigation'],['High / critical',data.high_critical,ShieldAlert,'Across saved scan versions'],['Monitoring',monitor.data?.status?.running?'Active':monitor.error?'Unavailable':'Stopped',Radio,'Local backend status']
    ].map(([label,value,Icon,note]:any)=><Card className="kpi" key={label}><div className="kpi-label">{label}<Icon size={18}/></div><strong>{value}</strong><small>{note}</small></Card>)}</div>
    <div className="analytics-grid"><Card><div className="section-heading"><div><h2>Findings by severity</h2><p>Recorded indicators across saved scan versions</p></div><Badge>CASE VIEW</Badge></div>{Object.keys(data.severity).length?<Suspense fallback={<Loading/>}><Chart data={data.severity}/></Suspense>:<Empty title="No saved findings"/>}</Card><Card><div className="section-heading"><div><h2>Detection coverage</h2><p>Methods represented in saved findings</p></div><Fingerprint size={19}/></div><div className="method-list">{Object.entries(data.methods).map(([method,count]:any)=><div key={method}><div><span className="method-icon"><ShieldCheck size={16}/></span><span>{method.replaceAll('_',' ')}</span><strong>{count}</strong></div><div className="meter"><i style={{width:Math.max(3,100*count/Math.max(1,...Object.values(data.methods) as number[]))+'%'}}/></div></div>)}</div>{!Object.keys(data.methods).length&&<Empty title="Awaiting analysis"/>}<p className="subtle-note">Scores and rule matches require evidence review.</p></Card></div>
    <div className="bottom-grid"><Card><div className="section-heading"><div><h2>Recent case activity</h2><p>Events from the verified audit chain</p></div><Link className="text-link" to="/audit">View audit trail <ArrowRight size={14}/></Link></div>{data.activity.length?<div className="activity-list">{data.activity.slice(0,8).map((event:any,i:number)=><Link to="/audit" key={i} className="activity-row" onClick={()=>setCaseId(event.case_id)}><span className="activity-icon"><Activity size={16}/></span><div><strong>{event.action.toLowerCase().replaceAll('_',' ')}</strong><small>{event.case_id}</small></div><time>{date(event.timestamp)}</time><ChevronIcon/></Link>)}</div>:<Empty/>}</Card><div className="quick-column"><Card className="quick-card"><span className="eyebrow">NEXT STEP</span><div className="quick-icon"><ScanLine size={28}/></div><h2>Follow the evidence.</h2><p>Run a bounded scan, review its findings, and preserve the analysis in your case.</p><Link className="button button-outline" to="/scanner">Open scanner <ArrowRight size={16}/></Link></Card><Card className="integrity-note"><ShieldCheck size={23}/><div><h3>Integrity is part of the workflow</h3><p>Original evidence stays unchanged. Every new case action uses the existing audit chain.</p></div></Card></div></div><p className="subtle-note">{data.scope}</p></>}
  </>
}
function ChevronIcon(){return <ArrowUpRight size={15}/>}
