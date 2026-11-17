import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, RefreshCw } from 'lucide-react'
import { useEvidence } from '../hooks/useEvidence'
import { api } from '../services/api'
import { Card, PageHeading, Loading, ErrorState, Badge, Pager, DataTable, Notice } from '../components/common'
import { Button } from '../components/ui/button'
export default function Audit(){
 const data=useEvidence();const [page,setPage]=useState(1);const result=useQuery({queryKey:['audit',data.caseId,page],queryFn:()=>api(data.base+'/audit?page_number='+page),enabled:!!data.caseId})
 return <><PageHeading title="Audit integrity" description="Verify the selected case’s chain without changing a single historical entry." action={<Button variant="outline" disabled={result.isFetching} onClick={()=>result.refetch()}><RefreshCw size={16}/>Verify selected case</Button>}/><div className="case-integrity-grid">{data.cases.map(c=><button className={'card case-integrity '+(data.caseId===c.case_id?'selected':'')} key={c.case_id} onClick={()=>{data.setCaseId(c.case_id);setPage(1)}}><ShieldCheck size={21}/><strong>{c.case_id}</strong><Badge tone={c.verified?'low':'critical'}>{c.verified?'Consistent':'Failed'}</Badge><small>{c.message}</small></button>)}</div><Card><h2>Selected case · {data.caseId||'none'}</h2>{result.isLoading?<Loading/>:result.error?<ErrorState error={result.error}/>:result.data?<><div className={'notice '+(result.data.verified?'':'error')}>{result.data.message}</div>{!result.data.verified&&<Notice>The failed history is preserved. Unverified entries are not presented as trusted case events. There is no repair or reset action.</Notice>}<DataTable rows={result.data.items}/><Pager page={page} total={result.data.total} onChange={setPage}/></>:<Notice>Select or create a case.</Notice>}</Card></>
}
