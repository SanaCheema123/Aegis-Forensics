import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Legend } from 'recharts'
import { metricDefinitions, modelLabel, type EvaluationRun } from '../../lib/evaluation'

export function OutcomeChart({run}:{run:EvaluationRun}) {
  const r=run.result
  const rows=[{name:'Normal labels',correct:r.tn,errors:r.fp},{name:'Attack labels',correct:r.tp,errors:r.fn}]
  return <div className="evaluation-chart" role="img" aria-label={`Decision outcomes: ${r.tn} true negatives, ${r.fp} false positives, ${r.tp} true positives, ${r.fn} false negatives`}>
    <ResponsiveContainer width="100%" height={250}><BarChart data={rows} margin={{top:12,right:8,left:-18,bottom:5}}>
      <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 4"/>
      <XAxis dataKey="name" tick={{fill:'var(--muted)',fontSize:12}} tickLine={false} axisLine={false}/><YAxis allowDecimals={false} tick={{fill:'var(--muted)',fontSize:11}} tickLine={false} axisLine={false}/>
      <Tooltip cursor={{fill:'var(--surface2)'}} contentStyle={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:9,color:'var(--text)'}}/>
      <Legend wrapperStyle={{fontSize:11,paddingTop:12}}/>
      <Bar name="Correct decisions" dataKey="correct" stackId="outcomes" fill="#9280ed" isAnimationActive={false} maxBarSize={66}/>
      <Bar name="Incorrect decisions" dataKey="errors" stackId="outcomes" fill="#d17978" radius={[5,5,0,0]} isAnimationActive={false} maxBarSize={66}/>
    </BarChart></ResponsiveContainer>
  </div>
}
export function ComparisonChart({runs}:{runs:EvaluationRun[]}) {
  const rows=metricDefinitions.map(({key,label})=>({name:label,...Object.fromEntries(runs.map(run=>[run.result.model,run.result[key]*100]))}))
  return <div className="evaluation-chart" role="img" aria-label="Comparison of accuracy, precision, recall and F1 on the same labeled source">
    <ResponsiveContainer width="100%" height={250}><BarChart data={rows} margin={{top:12,right:8,left:-18,bottom:5}}>
      <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 4"/><XAxis dataKey="name" tick={{fill:'var(--muted)',fontSize:11}} axisLine={false} tickLine={false}/><YAxis domain={[0,100]} tickFormatter={value=>`${value}%`} tick={{fill:'var(--muted)',fontSize:11}} axisLine={false} tickLine={false}/>
      <Tooltip cursor={{fill:'var(--surface2)'}} formatter={value=>`${Number(value).toFixed(2)}%`} contentStyle={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:9,color:'var(--text)'}}/>
      <Legend wrapperStyle={{fontSize:11,paddingTop:12}}/>{runs.map((run,i)=><Bar key={run.result.model} name={modelLabel(run.result.model)} dataKey={run.result.model} fill={run.result.model==='iforest'?'#548fc4':'#9280ed'} radius={[4,4,0,0]} isAnimationActive={false} maxBarSize={28}/>)}
    </BarChart></ResponsiveContainer>
  </div>
}
