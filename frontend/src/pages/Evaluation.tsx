import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Activity, ArrowRight, BarChart3, Check, CheckCircle2, ChevronDown, CircleHelp, Database, Fingerprint, FlaskConical, LoaderCircle, Play, Settings2, ShieldCheck, Target } from 'lucide-react'
import { useEvidence } from '../hooks/useEvidence'
import { api, post } from '../services/api'
import { Card, PageHeading, Notice, ErrorState, Technical, Loading, Badge } from '../components/common'
import { Button } from '../components/ui/button'
import { EvidenceSelect } from '../components/investigations/EvidenceSelect'
import { ModelControls } from './Scanner'
import { comparable, matrixCells, metricDefinitions, modelLabel, validEvaluation, type EvaluationConfig, type EvaluationResult, type EvaluationRun } from '../lib/evaluation'
import type { Job } from '../types'
import '../styles/analytics-pages.css'

const OutcomeChart=lazy(()=>import('../components/charts/EvaluationCharts').then(module=>({default:module.OutcomeChart})))
const ComparisonChart=lazy(()=>import('../components/charts/EvaluationCharts').then(module=>({default:module.ComparisonChart})))
const icons=[ShieldCheck,Target,Activity,BarChart3]

function ConfusionMatrix({run}:{run:EvaluationRun}) {
  const [selected,setSelected]=useState<typeof matrixCells[number]>(matrixCells[0])
  const r=run.result
  return <Card className="matrix-card"><div className="section-heading"><div><span className="panel-eyebrow">RECORD-LEVEL DECISIONS</span><h2>Confusion matrix</h2><p>Select a cell to understand the decision.</p></div><span className="chart-unit">{r.records} records</span></div>
    <div className="matrix-axis-label">PREDICTED DECISION</div>
    <div className="matrix-layout confusion-grid"><span aria-hidden="true"/><span>Not flagged</span><span>Flagged</span><span className="matrix-row-label">Actual<br/><strong>Normal</strong></span>
      {matrixCells.slice(0,2).map(cell=><button key={cell.key} className={`matrix-cell ${cell.tone} ${selected.key===cell.key?'selected':''}`} aria-label={`${cell.key.toUpperCase()}: ${r[cell.key]} ${cell.name.toLowerCase()} records`} aria-pressed={selected.key===cell.key} onClick={()=>setSelected(cell)}><span>{cell.key.toUpperCase()} <small>{cell.name}</small></span><strong>{r[cell.key]}</strong><small>{(r[cell.key]/r.records*100).toFixed(1)}% of records</small></button>)}
      <span className="matrix-row-label">Actual<br/><strong>Attack</strong></span>{matrixCells.slice(2).map(cell=><button key={cell.key} className={`matrix-cell ${cell.tone} ${selected.key===cell.key?'selected':''}`} aria-label={`${cell.key.toUpperCase()}: ${r[cell.key]} ${cell.name.toLowerCase()} records`} aria-pressed={selected.key===cell.key} onClick={()=>setSelected(cell)}><span>{cell.key.toUpperCase()} <small>{cell.name}</small></span><strong>{r[cell.key]}</strong><small>{(r[cell.key]/r.records*100).toFixed(1)}% of records</small></button>)}</div>
    <div className="matrix-explanation" aria-live="polite"><CircleHelp size={17}/><div><strong>{selected.name} · {r[selected.key]} records</strong><p>{selected.meaning} Actual label: {selected.actual.toLowerCase()}; model decision: {selected.predicted.toLowerCase()}.</p></div></div>
  </Card>
}

function Performance({run}:{run:EvaluationRun}) {
  return <div className="performance-kpis">{metricDefinitions.map((metric,i)=>{
    const Icon=icons[i], value=run.result[metric.key]*100
    return <Card key={metric.key} className="performance-kpi"><div><span>{metric.label}</span><Icon size={19}/></div><strong>{value.toFixed(2)}<small>%</small></strong><div className="performance-meter"><i style={{width:`${value}%`}}/></div><p>{metric.description}</p><details className="metric-definition"><summary>How it’s calculated</summary><p>{metric.formula}. When the denominator is zero, the existing evaluator reports zero.</p></details></Card>
  })}</div>
}

function Comparison({current,history}:{current:EvaluationRun;history:EvaluationRun[]}) {
  const other=[...history].reverse().find(run=>comparable(current,run))
  return <Card className="model-comparison"><div className="section-heading"><div><span className="panel-eyebrow">SHARED LABELED BENCHMARK</span><h2>Model comparison</h2><p>Compare binary decisions on the same source records.</p></div><Badge>{other?'Comparable runs':'Awaiting second model'}</Badge></div>
    {other?<><Suspense fallback={<Loading/>}><ComparisonChart runs={[current,other]}/></Suspense><div className="table-wrap"><table><caption className="sr-only">Comparable labeled evaluation metrics</caption><thead><tr><th>Model / split</th>{metricDefinitions.map(m=><th key={m.key}>{m.label}</th>)}</tr></thead><tbody>{[current,other].map(run=><tr key={run.result.model}><td><strong>{modelLabel(run.result.model)}</strong><small className="comparison-subtitle">{run.result.split} checkpoint{run.result.model==='xgboost'?` · threshold ${run.config.threshold}`:' · native anomaly decision'}</small></td>{metricDefinitions.map(m=><td key={m.key}>{(run.result[m.key]*100).toFixed(2)}%</td>)}</tr>)}</tbody></table></div></>:<div className="comparison-empty"><BarChart3 size={29}/><div><h3>Run the other model to compare</h3><p>Evaluate {current.result.model==='xgboost'?'Isolation Forest':'XGBoost'} on this exact dataset and checkpoint split. No comparison is filled in before both runs complete.</p></div></div>}
    <p className="comparison-footnote"><ShieldCheck size={15}/>Comparison requires matching case, evidence identity, SHA-256, sample count, label distribution, and split. XGBoost classification and Isolation Forest anomaly detection are different methods; only their labeled binary outcomes are compared, never their raw scores.</p>
  </Card>
}

export default function Evaluation(){const data=useEvidence();return <EvaluationWorkspace key={data.caseId+':'+data.evidenceId}/>}

function EvaluationWorkspace(){
  const data=useEvidence()
  const [model,setModel]=useState('xgboost'), [split,setSplit]=useState('random'), [threshold,setThreshold]=useState(.5), [approved,setApproved]=useState(false)
  const [history,setHistory]=useState<EvaluationRun[]>([]), [active,setActive]=useState<EvaluationRun|null>(null)
  const [pending,setPending]=useState<{id:string;config:EvaluationConfig}|null>(null), [resultError,setResultError]=useState<string|null>(null)
  const handled=useRef('')
  const evaluate=useMutation({mutationFn:(config:EvaluationConfig)=>post<Job>(data.base+'/evaluation',config),onSuccess:(job,config)=>{setPending({id:job.id,config});setResultError(null)}})
  const job=useQuery({queryKey:['evaluation-job',data.caseId,data.evidenceId,pending?.id],queryFn:()=>api<Job>(data.base+'/jobs/'+pending!.id),enabled:!!pending,
    refetchInterval:query=>['queued','running'].includes(query.state.data?.status||'queued')?1000:false})
  const cancel=useMutation({mutationFn:(id:string)=>post(data.base+'/jobs/'+id+'/cancel'),onSuccess:()=>{void job.refetch()}})
  useEffect(()=>{
    if (!pending || job.data?.status!=='completed' || handled.current===pending.id) return
    handled.current=pending.id
    const result=job.data.result as EvaluationResult
    if (!validEvaluation(result)||result.dataset.case_id!==data.caseId||result.dataset.id!==data.evidenceId
      ||result.model!==pending.config.model||result.split!==pending.config.split) {
      setResultError('This evaluation response is incomplete or belongs to a different context. No performance metrics are displayed for this run.');return
    }
    const run={result,config:pending.config}
    setActive(run);setHistory(previous=>[...previous.filter(item=>!(item.result.model===result.model&&item.result.split===result.split&&item.config.threshold===pending.config.threshold)),run].slice(-8))
  },[job.data,pending,data.caseId,data.evidenceId])
  const busy=evaluate.isPending||!!pending&&(!job.data||['queued','running'].includes(job.data.status))&&!job.error
  const configChanged=active&&(active.config.model!==model||active.config.split!==split||model==='xgboost'&&active.config.threshold!==threshold)
  const submit=()=>evaluate.mutate({evidence_id:data.evidenceId,model:model as EvaluationConfig['model'],split:split as EvaluationConfig['split'],threshold})
  const failure=evaluate.error||job.error||(cancel.variables===pending?.id&&cancel.error)||job.data?.status==='failed'&&new Error(job.data.error||'Evaluation could not complete.')||resultError
  return <div className="analytics-page evaluation-page">
    <PageHeading eyebrow="MODEL INTELLIGENCE / LABELED EVALUATION" title="Model evaluation" description="Measure detection decisions against source-aligned ground truth. Every metric begins with a real evaluation." action={<span className="catalog-readonly"><FlaskConical size={16}/> Labeled dataset analysis</span>}/>
    <div className="evaluation-scope-banner"><FlaskConical size={20}/><div><strong>Selected-file performance, not an independent test claim</strong><p>A demonstration sample does not establish deployment or full-dataset performance. This interface does not verify independence from checkpoint training data.</p></div><Badge>LIMITED EVALUATION SCOPE</Badge></div>
    <Card className="evaluation-setup"><div className="section-heading"><div><span className="panel-eyebrow">EVALUATION WORKSPACE</span><h2>Choose your benchmark</h2><p>Select saved evidence with explicit binary labels before running evaluation.</p></div><Database size={22}/></div>
      <EvidenceSelect/>
      <details className="expert-section configuration-panel" open={!active}><summary><Settings2 size={18}/><span>Evaluation configuration<small>Model, checkpoint split, and classification threshold</small></span><ChevronDown size={16}/></summary><ModelControls {...{model,setModel,split,setSplit,threshold,setThreshold}}/><p className="subtle-note">Labels and attack categories are excluded from prediction features. Isolation Forest uses its checkpoint’s native anomaly decision; the classification threshold applies only to XGBoost.</p></details>
      <div className="evaluation-run-row"><label className="checkbox-label"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)}/>This is an explicitly labeled evaluation dataset with valid 0/1 ground truth.</label><Button disabled={!approved||!data.evidenceId||busy} onClick={submit}>{busy?<LoaderCircle size={17} className="spin"/>:<Play size={15}/>} {busy?'Evaluating…':'Run labeled evaluation'}</Button></div>
      {failure&&<ErrorState error={failure instanceof Error?failure:new Error(String(failure))}/ >}
      {busy&&<div className="evaluation-progress" role="status"><LoaderCircle size={18} className="spin"/><span>{job.data?.status==='queued'?'Waiting for the analysis worker…':'Evaluating the selected checkpoint against recorded labels…'}</span></div>}
      {pending&&job.data?.cancellable&&<Button variant="outline" disabled={cancel.isPending} onClick={()=>cancel.mutate(pending.id)}>Cancel queued evaluation</Button>}
      {job.data?.status==='cancelled'&&<Notice>This evaluation was cancelled before it started. No results were generated.</Notice>}
    </Card>
    {active&&(busy||failure)&&<Notice>Results below are from the last completed run. The current attempt has not produced a new validated result.</Notice>}{!active?<Card className="evaluation-welcome"><div className="welcome-illustration"><BarChart3 size={38}/><span><Check size={15}/></span></div><span className="panel-eyebrow">READY WHEN YOUR DATA IS</span><h2>Your next evaluation, clearly explained.</h2><p>Run a labeled evaluation to reveal performance metrics, record-level decision outcomes, and checkpoint provenance. There are no prefilled scores.</p><div className="evaluation-empty-metrics">{metricDefinitions.map(m=><div key={m.key}><span>{m.label}</span><strong aria-label={m.label+' unavailable'}>—</strong></div>)}</div><div className="evaluation-steps"><span><i>1</i>Select labeled evidence</span><ArrowRight size={14}/><span><i>2</i>Configure the checkpoint</span><ArrowRight size={14}/><span><i>3</i>Review measured outcomes</span></div></Card>:<>
      <div className="evaluation-completed" role="status"><CheckCircle2 size={18}/><strong>Evaluation complete</strong><span>{modelLabel(active.result.model)} · {active.result.records.toLocaleString()} labeled records</span><Badge>ACTUAL API RESULT</Badge></div>
      {configChanged&&<Notice>The configuration has changed. Results below still describe the completed {modelLabel(active.result.model)} / {active.result.split} run. Run evaluation to measure the new configuration.</Notice>}
      {history.length>1&&<label className="completed-run-select">Completed run<select aria-label="Completed evaluation run" value={String(history.indexOf(active))} onChange={e=>setActive(history[Number(e.target.value)])}>{history.map((run,index)=><option key={index} value={index}>{modelLabel(run.result.model)} · {run.result.split}{run.result.model==='xgboost'?` · threshold ${run.config.threshold}`:''}</option>)}</select></label>}
      <Performance run={active}/>
      <Card className="evaluation-dataset"><div className="dataset-emblem"><Database size={23}/></div><div><span className="panel-eyebrow">EVALUATED SOURCE</span><h2>{active.result.dataset.filename}</h2><div className="dataset-facts"><span><strong>{active.result.records.toLocaleString()}</strong> records</span><span><strong>{active.result.tp+active.result.fn}</strong> attack labels</span><span><strong>{active.result.tn+active.result.fp}</strong> normal labels</span><span>{modelLabel(active.result.model)} · {active.result.split} split</span></div><code className="hash">SHA-256 {active.result.dataset.sha256}</code></div><Badge>{/demo/i.test(active.result.dataset.filename)?'Demonstration sample':'Selected labeled file'}</Badge></Card>
      <div className="evaluation-visuals"><ConfusionMatrix run={active}/><Card><div className="section-heading"><div><span className="panel-eyebrow">GROUND TRUTH VS. DECISIONS</span><h2>Decision outcomes</h2><p>Correct and incorrect decisions by actual class.</p></div><BarChart3 size={21}/></div><Suspense fallback={<Loading/>}><OutcomeChart run={active}/></Suspense><div className="outcome-totals"><span><i className="legend-correct"/>{active.result.tn+active.result.tp} correct decisions</span><span><i className="legend-error"/>{active.result.fp+active.result.fn} incorrect decisions</span></div><p className="subtle-note">Class labels are ground truth for this file. A model flag alone is not confirmed malicious activity.</p></Card></div>
      <Comparison current={active} history={history}/>
      <Card className="evaluation-expert"><div className="section-heading"><div><h2>Scope & provenance</h2><p>What this measurement can support, and the context needed to reproduce it.</p></div><Fingerprint size={21}/></div><Notice>{active.result.limitation}</Notice><p className="evaluation-limit-copy">Evaluation correctness is measured against this file’s labels. Neither an anomaly score nor a classification probability guarantees that an event is malicious. ROC-AUC is unavailable from this flagged-only response; no curve or score is inferred.</p><Technical value={{dataset:active.result.dataset,request:active.config,provenance:active.result.provenance,confusion_matrix:active.result.confusion_matrix}} label="Expert details: checkpoint and feature provenance"/></Card>
    </>}
  </div>
}
