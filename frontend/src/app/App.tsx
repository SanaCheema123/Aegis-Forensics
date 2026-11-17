import { lazy, Suspense } from 'react'
import { Routes, Route, Link } from 'react-router-dom'
import { Shell } from '../components/layout/Shell'
import { Loading, Empty } from '../components/common'
const Dashboard=lazy(()=>import('../pages/Dashboard'))
const Scanner=lazy(()=>import('../pages/Scanner'))
const Investigations=lazy(()=>import('../pages/Investigations'))
const Evidence=lazy(()=>import('../pages/EvidenceVault'))
const Timeline=lazy(()=>import('../pages/Timeline'))
const Reports=lazy(()=>import('../pages/Reports'))
const Evaluation=lazy(()=>import('../pages/Evaluation'))
const Audit=lazy(()=>import('../pages/Audit'))
const Monitoring=lazy(()=>import('../pages/Monitoring'))
const Rules=lazy(()=>import('../pages/Rules'))
const Settings=lazy(()=>import('../pages/Settings'))
export default function App(){return <Shell><Suspense fallback={<Loading/>}><Routes><Route path="/" element={<Dashboard/>}/><Route path="/scanner" element={<Scanner/>}/><Route path="/investigations" element={<Investigations/>}/><Route path="/anomalies" element={<Investigations anomalies/>}/><Route path="/evidence" element={<Evidence/>}/><Route path="/timeline" element={<Timeline/>}/><Route path="/reports" element={<Reports/>}/><Route path="/evaluation" element={<Evaluation/>}/><Route path="/audit" element={<Audit/>}/><Route path="/monitoring" element={<Monitoring/>}/><Route path="/rules" element={<Rules/>}/><Route path="/settings" element={<Settings/>}/><Route path="*" element={<Empty title="Page not found"><Link to="/">Return to the dashboard</Link></Empty>}/></Routes></Suspense></Shell>}
