import { useQuery } from '@tanstack/react-query'
import { useWorkspace } from '../app/context'
import { api, enc } from '../services/api'
import type { Collection, Evidence } from '../types'

export function useEvidence() {
  const workspace = useWorkspace()
  const base = '/cases/' + enc(workspace.caseId)
  const query = useQuery({ queryKey: ['evidence', workspace.caseId], queryFn: () => api<Collection<Evidence>>(base + '/evidence?page_size=100'), enabled: !!workspace.caseId })
  const firstPage = query.data?.items || []
  const extra = useQuery({queryKey:['evidence-detail',workspace.caseId,workspace.evidenceId],
    queryFn:()=>api<Evidence>(base+'/evidence/'+enc(workspace.evidenceId)),
    enabled:!!workspace.caseId&&!!workspace.evidenceId&&query.isSuccess&&!firstPage.some(e=>e.id===workspace.evidenceId)})
  const items = extra.data ? [...firstPage, extra.data] : firstPage
  const evidenceId = workspace.evidenceId || items[0]?.id || ''
  return { ...workspace, base, items, evidenceId, evidence:items.find(e=>e.id===evidenceId), query,
    selectionError:extra.error, source: base+'/evidence/'+enc(evidenceId) }
}
