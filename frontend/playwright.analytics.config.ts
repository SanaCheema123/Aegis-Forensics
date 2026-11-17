import { defineConfig } from '@playwright/test'
import base from './playwright.config'
export default defineConfig({
  ...base,
  use:{...base.use,baseURL:'http://127.0.0.1:5174'},
  reporter:[['list'],['json',{outputFile:'../audit_artifacts/ui_redesign_browser_results.json'}]],
  webServer:[
    {command:'..\\.venv\\Scripts\\python.exe e2e/isolated_api.py',url:'http://127.0.0.1:8001/api/v1/health',timeout:60000,reuseExistingServer:false},
    {command:'npm run dev -- --config vite.acceptance.config.ts',url:'http://127.0.0.1:5174',timeout:60000,reuseExistingServer:false},
  ],
})
