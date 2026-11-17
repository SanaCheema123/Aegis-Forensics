import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { catalogRules, tokenizeSource } from './ruleCatalog'
import { comparable, validEvaluation, type EvaluationRun } from './evaluation'

describe('Display-only rule catalog',()=>{
  it('extracts individual declarations, tags and typed metadata without reading comments as rules',()=>{
    const source='// rule Fake { }\nprivate rule Example : test local { meta: description = "A \\"quoted\\" name" severity = "high" enabled = false priority = -2 strings: $a = /x{2,}/ condition: $a }\nrule Other { condition: true }'
    const rules=catalogRules([{name:'example.yar',category:'YARA',content:source}])
    expect(rules.map(r=>r.name)).toEqual(['Example','Other'])
    expect(rules[0].tags).toEqual(['test','local'])
    expect(rules[0].metadata.enabled).toBe(false)
    expect(rules[0].metadata.priority).toBe(-2)
    expect(rules[0].severity).toBe('High')
    expect(rules[1].severity).toBe('Not specified')
    expect(rules[1].description).toBeNull()
    expect(rules[0].source).toBe(source)
  })
  it('preserves exact source through highlighting, including HTML-like strings and regex braces',()=>{
    const source='/* comment { */\nrule A { strings: $x="<script>hi</script>" $r=/(ab){2,3}/ condition: any of them }\r\n'
    expect(tokenizeSource(source).map(t=>t.text).join('')).toBe(source)
    expect(catalogRules([{name:'a.yar',category:'YARA',content:source}])).toHaveLength(1)
  })
  it('retains unrecognized files as source-only entries instead of fabricating metadata',()=>{
    const [entry]=catalogRules([{name:'partial.yar',category:'YARA',content:'rule Incomplete {'}])
    expect(entry.parsed).toBe(false)
    expect(entry.metadata).toEqual({})
    expect(entry.source).toBe('rule Incomplete {')
  })
  it('reads every declaration in the actual local rule files and preserves every source byte',()=>{
    const directory=resolve('../yara_rules')
    const files=readdirSync(directory).filter(f=>f.endsWith('.yar')).map(name=>({name,category:'YARA',content:readFileSync(resolve(directory,name),'utf8')}))
    const rules=catalogRules(files)
    expect(rules.length).toBe(files.reduce((count,file)=>count+(file.content.match(/\brule\s+\w+/g)||[]).length,0))
    expect(rules.every(rule=>rule.parsed&&rule.description&&rule.metadata.severity)).toBe(true)
    for(const file of files)expect(tokenizeSource(file.content).map(t=>t.text).join('')).toBe(file.content)
  })
})

const example=(model:'xgboost'|'iforest'):EvaluationRun=>({
  config:{model,split:'random',threshold:.5,evidence_id:'source'},
  result:{records:4,flagged:2,tn:1,fp:1,fn:1,tp:1,accuracy:.5,precision:.5,recall:.5,f1:.5,confusion_matrix:[[1,1],[1,1]],
    dataset:{id:'source',sha256:'a'.repeat(64),filename:'fixture.csv',case_id:'CASE-A'},model,split:'random',limitation:'Fixture only',provenance:{}}
})
describe('Measured performance and comparison guards',()=>{
  it('allows binary-outcome comparison for different methods on identical labeled source and split',()=>expect(comparable(example('xgboost'),example('iforest'))).toBe(true))
  it('rejects comparisons across cases, evidence versions, splits, sample counts and label distributions',()=>{
    for(const change of [
      (run:EvaluationRun)=>{run.result.dataset.case_id='CASE-B'},
      (run:EvaluationRun)=>{run.result.dataset.sha256='b'.repeat(64)},
      (run:EvaluationRun)=>{run.result.dataset.id='other'},
      (run:EvaluationRun)=>{run.result.split='official'},
      (run:EvaluationRun)=>{run.result.records=5},
      (run:EvaluationRun)=>{run.result.tn=0;run.result.fn=2;run.result.confusion_matrix=[[0,1],[2,1]]},
    ]){const other=example('iforest');change(other);expect(comparable(example('xgboost'),other)).toBe(false)}
    expect(comparable(example('xgboost'),example('xgboost'))).toBe(false)
  })
  it('does not treat missing, nonfinite or inconsistent metrics as an evaluation',()=>{
    for(const value of [NaN,Infinity,-1,1.01]){const run=example('xgboost');run.result.accuracy=value;expect(validEvaluation(run.result)).toBe(false)}
    const run=example('xgboost');run.result.confusion_matrix=[[1,0],[1,1]];expect(validEvaluation(run.result)).toBe(false)
    expect(validEvaluation(null as unknown as EvaluationRun['result'])).toBe(false)
  })
})
