import { mergeConfig } from 'vite'
import base from './vite.config'

// Acceptance-only proxy: preserve the API's existing allowed frontend origin
// while using separate loopback ports. Production configuration is unchanged.
export default mergeConfig(base, {
  server: { port: 5174, proxy: { '/api': {
    target:'http://127.0.0.1:8001', changeOrigin:true,
    configure(proxy) { proxy.on('proxyReq', outgoing => outgoing.setHeader('Origin','http://127.0.0.1:5173')) },
  } } },
})
