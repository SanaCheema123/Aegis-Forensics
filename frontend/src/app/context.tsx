import { createContext, useContext, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import type { Case, Collection } from '../types'

type Workspace = { caseId: string; setCaseId: (id: string) => void; evidenceId: string; setEvidenceId: (id: string) => void; cases: Case[]; loading: boolean; error: Error | null }
const Context = createContext<Workspace | null>(null)
export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [selected, select] = useState(localStorage.getItem('aegis.case') || '')
  const [evidence, setEvidence] = useState<Record<string,string>>({})
  const result = useQuery({ queryKey: ['cases'], queryFn: () => api<Collection<Case>>('/cases') })
  const cases = result.data?.items || []
  const caseId = cases.some(c => c.case_id === selected) ? selected : (cases.find(c => c.case_id === 'FINAL-TEST-001' && c.verified)?.case_id || cases.find(c => c.verified)?.case_id || cases[0]?.case_id || '')
  const setCaseId = (id: string) => { select(id); localStorage.setItem('aegis.case', id) }
  return <Context.Provider value={{ caseId, setCaseId, evidenceId: evidence[caseId] || '', setEvidenceId: id => setEvidence(e => ({...e, [caseId]: id})), cases, loading: result.isLoading, error: result.error }}>{children}</Context.Provider>
}
export function useWorkspace() { const context = useContext(Context); if (!context) throw new Error('Workspace provider required'); return context }
