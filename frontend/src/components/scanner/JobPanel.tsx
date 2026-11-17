import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, LoaderCircle } from 'lucide-react'
import { api, post } from '../../services/api'
import { Badge, Card, ErrorState, Notice, Technical } from '../common'
import { Button } from '../ui/button'
import type { Job } from '../../types'
export function JobPanel({base,id,onComplete}:{base:string;id:string;onComplete?:(result:Record<string,any>)=>void}){
  const client=useQueryClient()
  const result=useQuery({queryKey:['job',base,id],queryFn:()=>api<Job>(base+'/jobs/'+id),refetchInterval:q=>['queued','running'].includes(q.state.data?.status||'queued')?1000:false})
  const job=result.data
  const cancel=useMutation({mutationFn:()=>post(base+'/jobs/'+id+'/cancel'),onSuccess:()=>client.invalidateQueries({queryKey:['job',base,id]})})
  useEffect(()=>{if(job?.status==='completed'){client.invalidateQueries({queryKey:['evidence']});client.invalidateQueries({queryKey:['vault']});client.invalidateQueries({queryKey:['dashboard']});client.invalidateQueries({queryKey:['scans']});onComplete?.(job.result||{})}},[job?.status])
  if(result.error)return <ErrorState error={result.error}/>
  return <Card className="job-panel">
    <div className="section-heading"><h2>{job?.status==='completed'?<CheckCircle2 size={20}/>:<LoaderCircle size={20} className={job?.status==='running'?'spin':''}/>} {job?.phase||'Loading job'}</h2><Badge tone={job?.status==='completed'?'low':''}>{job?.status||'pending'}</Badge></div>
    <code className="hash">Job {id}</code>
    {job?.progress&&<p>{job.progress.checked} of {job.progress.total} files checked</p>}
    {job?.error&&<ErrorState error={job.error}/ >}
    {cancel.error&&<ErrorState error={cancel.error}/ >}
    {job?.cancellable&&<Button variant="outline" disabled={cancel.isPending} onClick={()=>cancel.mutate()}>Cancel queued job</Button>}
    {job?.status==='running'&&<p className="subtle-note">One bounded operation is running. This engine does not support cancellation after execution begins.</p>}
    {job?.status==='completed'&&job.result&&<>
      {job.result.input_records!=null&&<div className="metric-row"><div><span>Input records</span><strong>{job.result.input_records}</strong></div><div><span>Flagged records</span><strong>{job.result.flagged_records}</strong></div></div>}
      {job.result.provenance?.score_meaning&&<Notice>{job.result.provenance.score_meaning}</Notice>}
      {job.result.yara_available===false&&<Notice>YARA is unavailable; no YARA coverage is claimed.</Notice>}
      {job.result.warnings?.map((warning:string,i:number)=><Notice key={i}>{warning}</Notice>)}
      <Technical value={job.result} label="Analysis result and provenance"/>
    </>}
  </Card>
}
