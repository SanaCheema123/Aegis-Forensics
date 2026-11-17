export type EvaluationConfig = { model: 'xgboost'|'iforest'; split: 'random'|'official'; threshold: number; evidence_id: string }
export type EvaluationResult = {
  records: number; flagged: number; tn: number; fp: number; fn: number; tp: number
  accuracy: number; precision: number; recall: number; f1: number; confusion_matrix: number[][]
  dataset: { id: string; sha256: string; filename: string; case_id: string }
  model: 'xgboost'|'iforest'; split: 'random'|'official'; limitation: string
  provenance: Record<string, unknown>
}
export type EvaluationRun = { result: EvaluationResult; config: EvaluationConfig }
export const modelLabel = (model: string) => model==='xgboost'?'XGBoost':model==='iforest'?'Isolation Forest':model
export const metricDefinitions = [
  {key:'accuracy',label:'Accuracy',description:'Correct decisions across all labeled records.',formula:'(TP + TN) / all records'},
  {key:'precision',label:'Precision',description:'Flagged records that carry an attack label.',formula:'TP / (TP + FP)'},
  {key:'recall',label:'Recall',description:'Attack-labeled records the model flagged.',formula:'TP / (TP + FN)'},
  {key:'f1',label:'F1-score',description:'Harmonic mean of precision and recall.',formula:'2 × precision × recall / (precision + recall)'},
] as const
export function validEvaluation(result: EvaluationResult) {
  if (!result || !result.dataset?.sha256 || !result.provenance || !['xgboost','iforest'].includes(result.model)) return false
  const counts=[result.tn,result.fp,result.fn,result.tp]
  return counts.every(n=>Number.isInteger(n)&&n>=0)&&Number.isInteger(result.records)&&result.records>0
    && counts.reduce((a,b)=>a+b,0)===result.records && result.flagged===result.tp+result.fp
    && metricDefinitions.every(({key})=>Number.isFinite(result[key])&&result[key]>=0&&result[key]<=1)
    && JSON.stringify(result.confusion_matrix)===JSON.stringify([[result.tn,result.fp],[result.fn,result.tp]])
}
export function comparable(a: EvaluationRun, b: EvaluationRun) {
  return validEvaluation(a.result)&&validEvaluation(b.result)&&a.result.model!==b.result.model
    && a.result.dataset.case_id===b.result.dataset.case_id && a.result.dataset.id===b.result.dataset.id
    && a.result.dataset.sha256===b.result.dataset.sha256 && a.result.split===b.result.split
    && a.result.records===b.result.records && a.result.tp+a.result.fn===b.result.tp+b.result.fn
    && a.result.tn+a.result.fp===b.result.tn+b.result.fp
}
export const matrixCells = [
  {key:'tn',name:'True negative',actual:'Normal',predicted:'Not flagged',meaning:'Normal-labeled records correctly left unflagged.',tone:'correct'},
  {key:'fp',name:'False positive',actual:'Normal',predicted:'Flagged',meaning:'Normal-labeled records flagged for review.',tone:'error'},
  {key:'fn',name:'False negative',actual:'Attack',predicted:'Not flagged',meaning:'Attack-labeled records the model did not flag.',tone:'error'},
  {key:'tp',name:'True positive',actual:'Attack',predicted:'Flagged',meaning:'Attack-labeled records correctly flagged.',tone:'correct'},
] as const
