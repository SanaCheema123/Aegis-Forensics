import { defineConfig } from '@playwright/test'
export default defineConfig({
 testDir:'./e2e',workers:1,timeout:120000,expect:{timeout:15000},
 use:{baseURL:'http://127.0.0.1:5173',channel:'chrome',headless:true,trace:'retain-on-failure',viewport:{width:1440,height:1000}},
 reporter:[['list'],['json',{outputFile:'../audit_artifacts/migration_browser_results.json'}]],
 outputDir:'test-results',
 webServer:[
  {command:'..\\.venv\\Scripts\\python.exe ..\\scripts\\acceptance_server.py',url:'http://127.0.0.1:8000/api/v1/health',timeout:60000,reuseExistingServer:false},
  {command:'npm run dev',url:'http://127.0.0.1:5173',timeout:60000,reuseExistingServer:false},
 ],
})
