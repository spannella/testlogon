# Page snapshot

```yaml
- generic [ref=e3]:
  - generic [ref=e4]: "[plugin:vite:import-analysis] Failed to resolve import \"axios\" from \"src/api/endpoints/groups.ts\". Does the file exist?"
  - generic [ref=e5]: /home/ubuntu/testlogon/frontend/src/api/endpoints/groups.ts:3:18
  - generic [ref=e6]: "1 | import { api } from \"@/api/client\"; 2 | import axios from \"axios\"; | ^ 3 | export const createGroup = (data) => api.post(\"/ui/groups\", data); 4 | export const listMyGroups = () => api.get(\"/ui/groups\");"
  - generic [ref=e7]: at TransformPluginContext._formatLog (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:42528:41) at TransformPluginContext.error (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:42525:16) at normalizeUrl (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:40504:23) at process.processTicksAndRejections (node:internal/process/task_queues:95:5) at async file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:40623:37 at async Promise.all (index 1) at async TransformPluginContext.transform (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:40550:7) at async EnvironmentPluginContainer.transform (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:42323:18) at async loadAndTransform (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:35739:27) at async viteTransformMiddleware (file:///home/ubuntu/testlogon/frontend/node_modules/vite/dist/node/chunks/dep-D4NMHUTW.js:37254:24
  - generic [ref=e8]:
    - text: Click outside, press Esc key, or fix the code to dismiss.
    - text: You can also disable this overlay by setting
    - code [ref=e9]: server.hmr.overlay
    - text: to
    - code [ref=e10]: "false"
    - text: in
    - code [ref=e11]: vite.config.ts
    - text: .
```