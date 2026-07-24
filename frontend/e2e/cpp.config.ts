// Central API base for e2e specs.
// Defaults to the Python backend (http://localhost:8000) so existing runs are
// unchanged. For the C++ backend, override with E2E_API_BASE, e.g.
//   E2E_API_BASE="https://192.168.0.82:8443" npx playwright test
export const API = process.env.E2E_API_BASE ?? "http://localhost:8000";
