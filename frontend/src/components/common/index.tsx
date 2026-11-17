import { useState, type ReactNode } from 'react'
import { AlertCircle, ChevronLeft, ChevronRight, Database, LoaderCircle, X } from 'lucide-react'
import * as Dialog from '@radix-ui/react-dialog'
import { Button } from '../ui/button'

export function Card({ children, className = '' }: {children: ReactNode; className?: string}) { return <section className={'card ' + className}>{children}</section> }
export function PageHeading({ eyebrow='INVESTIGATION CONSOLE', title, description, action }: {eyebrow?:string; title:string; description:string; action?:ReactNode}) { return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div> }
export function ErrorState({ error }: {error: unknown}) { return <div className="notice error" role="alert"><AlertCircle size={18}/><span>{error instanceof Error ? error.message : String(error)}</span></div> }
export function Empty({ title='No records yet', children }: {title?: string; children?: ReactNode}) { return <div className="empty"><Database size={30}/><h3>{title}</h3><p>{children || 'Records will appear here when they are available in the selected case.'}</p></div> }
export function Loading() { return <div className="loading" role="status"><LoaderCircle className="spin" size={20}/> Loading verified records…</div> }
export function Notice({ children }: {children:ReactNode}) { return <div className="notice">{children}</div> }
export function Badge({ children, tone='' }: {children:ReactNode; tone?:string}) { return <span className={'badge ' + tone.toLowerCase()}>{children}</span> }
export function Pager({ page, total, size=25, onChange }: {page:number; total:number; size?:number; onChange:(page:number)=>void}) { return <div className="pager"><span>{total ? `${(page-1)*size+1}–${Math.min(page*size,total)} of ${total}` : '0 records'}</span><div><Button variant="outline" aria-label="Previous page" disabled={page<=1} onClick={()=>onChange(page-1)}><ChevronLeft size={16}/></Button><Button variant="outline" aria-label="Next page" disabled={page*size>=total} onClick={()=>onChange(page+1)}><ChevronRight size={16}/></Button></div></div> }
export function Technical({ value, label='Technical details' }: {value:unknown; label?:string}) { return <details className="technical"><summary>{label}</summary><pre>{JSON.stringify(value,null,2)}</pre></details> }
export function Drawer({ title, trigger, children }: {title:string; trigger:ReactNode; children:ReactNode}) { return <Dialog.Root><Dialog.Trigger asChild>{trigger}</Dialog.Trigger><Dialog.Portal><Dialog.Overlay className="overlay"/><Dialog.Content className="drawer"><div className="drawer-heading"><Dialog.Title>{title}</Dialog.Title><Dialog.Close asChild><Button variant="ghost" aria-label="Close details"><X size={20}/></Button></Dialog.Close></div><Dialog.Description className="muted">Recorded evidence and source details for this selection.</Dialog.Description>{children}</Dialog.Content></Dialog.Portal></Dialog.Root> }
export function DataTable({ rows }: {rows:Record<string,unknown>[]}) {
  const [sort,setSort] = useState<{key:string; desc:boolean}>({key:'',desc:false})
  if (!rows.length) return <Empty/>
  const allKeys = Array.from(new Set(rows.flatMap(Object.keys)))
  const keys = (allKeys.includes('_source') ? ['_source', ...allKeys.filter(key=>key!=='_source')] : allKeys).slice(0,12)
  const sorted = [...rows].sort((a,b)=>sort.key ? String(a[sort.key]??'').localeCompare(String(b[sort.key]??''), undefined,{numeric:true})*(sort.desc?-1:1) : 0)
  return <div className="table-wrap"><table><thead><tr>{keys.map(key=><th key={key}><button title="Sort this page" onClick={()=>setSort({key,desc:sort.key===key&&!sort.desc})}>{key.replaceAll('_',' ')} {sort.key===key?(sort.desc?'↓':'↑'):''}</button></th>)}</tr></thead><tbody>{sorted.map((row,i)=><tr key={i}>{keys.map(key=><td key={key}>{typeof row[key]==='object'?<code>{JSON.stringify(row[key])}</code>:String(row[key]??'—')}</td>)}</tr>)}</tbody></table></div>
}
