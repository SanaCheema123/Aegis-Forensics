const BASE = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/$/, '')
let token = ''
export class APIError extends Error { constructor(message: string, public status: number) { super(message) } }
export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method || 'GET'
  if (method !== 'GET' && !token) token = (await api<{csrf_token:string}>('/health')).csrf_token
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (method !== 'GET') headers.set('X-Aegis-Token', token)
  const response = await fetch(BASE + path, { ...options, headers })
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'The local API is unavailable.' }))
    if (response.status === 403) token = ''
    throw new APIError(typeof error.detail === 'string' ? error.detail : 'Request validation failed.', response.status)
  }
  return response.json()
}
export const post = <T = any>(path: string, body: unknown = {}) => api<T>(path, { method: 'POST', body: JSON.stringify(body) })
export async function download(path: string, filename: string) {
  const response = await fetch(BASE + path)
  if (!response.ok) throw new Error((await response.json()).detail || 'Export validation failed.')
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export const enc = encodeURIComponent
