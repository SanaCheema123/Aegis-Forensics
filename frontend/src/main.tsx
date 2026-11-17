import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './app/App'
import { WorkspaceProvider } from './app/context'
import './styles/index.css'
document.documentElement.dataset.theme=localStorage.getItem('aegis.theme')||'dark'
const client=new QueryClient({defaultOptions:{queries:{retry:1,refetchOnWindowFocus:false,staleTime:15000}}})
createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={client}><BrowserRouter><WorkspaceProvider><App/></WorkspaceProvider></BrowserRouter></QueryClientProvider></StrictMode>)
