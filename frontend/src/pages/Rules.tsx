import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowUpRight, FileCode2, Search, ShieldCheck, ShieldAlert, SlidersHorizontal, Tag, X } from 'lucide-react'
import { api } from '../services/api'
import { Card, PageHeading, Loading, ErrorState, Notice, Empty, Badge, Drawer, Pager } from '../components/common'
import { Button } from '../components/ui/button'
import { SourceCode } from '../components/common/SourceCode'
import { catalogRules, type CatalogRule, type RuleFile } from '../lib/ruleCatalog'
import type { Collection } from '../types'
import '../styles/analytics-pages.css'

function RuleDetails({rule}:{rule:CatalogRule}) {
  return <div className="rule-detail">
    <div className="detail-badges"><Badge tone={rule.severity}>{rule.severity}</Badge><Badge>{rule.type}</Badge></div>
    <h2 className="rule-detail-title">{rule.name.replaceAll('_',' ')}</h2>
    <p className="detail-description">{rule.description || 'A description was not provided in this source.'}</p>
    <dl className="identity-list"><div><dt>{rule.parsed?'Rule identifier':'Source entry'}</dt><dd><code>{rule.name}</code></dd></div><div><dt>Source file</dt><dd>{rule.filename}</dd></div><div><dt>Declaration</dt><dd>{rule.parsed?'Line '+rule.line:'Not available'}</dd></div></dl>
    <h3>Recorded metadata</h3>{!rule.parsed&&<Notice>This file could not be parsed for display. Its original API-provided source remains available below.</Notice>}
    {Object.keys(rule.metadata).length?<dl className="identity-list">{Object.entries(rule.metadata).map(([key,value])=><div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{String(value)}</dd></div>)}</dl>:<p className="muted">No metadata could be read from this source.</p>}
    {!!rule.tags.length&&<><h3>Declared tags</h3><div className="detail-badges">{rule.tags.map(tag=><Badge key={tag}>{tag}</Badge>)}</div></>}
    <details className="expert-section source-section"><summary><FileCode2 size={17}/><span>View Source Code<small>Complete API-provided file · {rule.filename}</small></span></summary><p className="subtle-note">The full file is preserved below, including other declarations and imports. Metadata above is extracted for display only; this interface does not compile or modify rules.</p>{rule.source.length>=100000&&<Notice>The API caps each source response at 100,000 characters. This file may be truncated; the original local file is required to verify its complete source.</Notice>}<SourceCode source={rule.source}/></details>
  </div>
}

export default function Rules() {
  const [q,setQ]=useState(''), [severity,setSeverity]=useState(''), [type,setType]=useState(''), [file,setFile]=useState(''), [page,setPage]=useState(1)
  const result=useQuery({queryKey:['rules'],queryFn:()=>api<Collection<RuleFile>>('/rules')})
  const rules=useMemo(()=>catalogRules(result.data?.items||[]),[result.data])
  const rows=rules.filter(rule=>(!severity||rule.severity===severity)&&(!type||rule.type===type)&&(!file||rule.filename===file)
    && [rule.name,rule.filename,rule.description,...Object.values(rule.metadata),...rule.tags,rule.definition].join(' ').toLowerCase().includes(q.toLowerCase()))
  const reset=()=>{setQ('');setSeverity('');setType('');setFile('');setPage(1)}
  const filtered=!!(q||severity||type||file)
  return <div className="analytics-page rules-page">
    <PageHeading eyebrow="DETECTION LIBRARY / RULE CATALOG" title="Threat rules" description="Understand what your detection rules look for, and inspect the evidence behind every definition." action={<span className="catalog-readonly"><ShieldCheck size={16}/> Read-only catalog</span>}/>
    <div className="catalog-summary">
      <Card><span className="summary-icon violet"><ShieldCheck size={21}/></span><div><small>Detection rules</small><strong>{result.isLoading?'—':rules.filter(r=>r.parsed).length}</strong></div><span>From local source declarations</span></Card>
      <Card><span className="summary-icon blue"><FileCode2 size={21}/></span><div><small>Source files</small><strong>{result.isLoading?'—':result.data?.items.length??'—'}</strong></div><span>Original definitions preserved</span></Card>
      <Card><span className="summary-icon amber"><ShieldAlert size={21}/></span><div><small>Severity documented</small><strong>{result.isLoading?'—':rules.filter(r=>r.severity!=='Not specified').length}</strong></div><span>Only explicit source metadata</span></Card>
    </div>
    <Card className="catalog-toolbar">
      <div className="section-heading"><div><h2>Detection rule library</h2><p>Search definitions, descriptions, metadata, and source content.</p></div><SlidersHorizontal size={19}/></div>
      <div className="catalog-filters"><label className="catalog-search"><Search size={18}/><input aria-label="Search detection rules" placeholder="Search rules, techniques, or descriptions…" value={q} onChange={e=>{setQ(e.target.value);setPage(1)}}/></label>
        <label>Severity<select aria-label="Severity" value={severity} onChange={e=>{setSeverity(e.target.value);setPage(1)}}><option value="">All severities</option>{Array.from(new Set(rules.map(r=>r.severity))).map(s=><option key={s}>{s}</option>)}</select></label>
        <label>Type<select aria-label="Rule type" value={type} onChange={e=>{setType(e.target.value);setPage(1)}}><option value="">All types</option>{Array.from(new Set(rules.map(r=>r.type))).map(t=><option key={t}>{t}</option>)}</select></label>
        <label>Source file<select aria-label="Rule source file" value={file} onChange={e=>{setFile(e.target.value);setPage(1)}}><option value="">All source files</option>{result.data?.items.map(f=><option key={f.name}>{f.name}</option>)}</select></label>
      </div>
      <div className="catalog-results-count" aria-live="polite"><span>{rows.length} {rows.length===1?'definition':'definitions'}{filtered?' matching filters':' in this catalog'}</span>{filtered&&<Button variant="ghost" onClick={reset}><X size={14}/>Clear filters</Button>}</div>
    </Card>
    {result.isLoading?<Loading/>:result.error?<ErrorState error={result.error}/>:!rows.length?<Card><Empty title={rules.length?'No matching rules':'No rule sources available'}>{rules.length?'Try a different phrase or clear the filters.':'The API has not returned any local rule files.'}</Empty>{filtered&&<Button variant="outline" onClick={reset}>Clear filters</Button>}</Card>:<>
      <div className="rule-card-grid">{rows.slice((page-1)*9,page*9).map(rule=><Card key={rule.id} className="detection-rule-card"><div className="rule-card-top"><span className="rule-symbol"><ShieldCheck size={21}/></span><div className="detail-badges"><Badge>{rule.type}</Badge><Badge tone={rule.severity}>{rule.severity}</Badge></div></div>
        <h2>{rule.name.replaceAll('_',' ')}</h2><code className="rule-identifier">{rule.name}</code><p className="rule-description">{rule.description||'No description recorded in the source metadata.'}</p>
        <div className="rule-metadata-line"><Tag size={14}/><span>{typeof rule.metadata.mitre==='string'?rule.metadata.mitre:rule.tags.length?rule.tags.join(' · '):'No technique mapping recorded'}</span></div>
        <div className="rule-card-footer"><span><FileCode2 size={14}/>{rule.filename}</span><Drawer title="Rule details" trigger={<Button variant="outline" aria-label={'View Rule Details: '+rule.name}>View Rule Details <ArrowUpRight size={14}/></Button>}><RuleDetails rule={rule}/></Drawer></div>
      </Card>)}</div><Pager page={page} size={9} total={rows.length} onChange={setPage}/>
    </>}
    <Notice>Metadata is read from the returned YARA definitions. A definition does not establish that a rule is enabled or that it has detected an event. Editing is unavailable.</Notice>
    {result.data&&result.data.total>result.data.items.length&&<Notice>The API returned only part of the source-file catalog. Counts and filters cover the returned files.</Notice>}
  </div>
}
