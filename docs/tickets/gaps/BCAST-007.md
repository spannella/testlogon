# BCAST-007 Gap List

- [LOW] Live-session sidebar badge not implemented — `frontend/src/components/layout/Sidebar.tsx` — `Radio` icon renders without dynamic pulsing green dot for active broadcasts — Fix: add `useQuery` for `["broadcast", "sessions", "live-count"]` + conditional badge render — Effort: S
- [LOW] No dedicated E2E navigation spec — `frontend/e2e/` — `broadcast-navigation.spec.ts` (or `broadcast-nav.spec.ts`) does not exist; nav coverage only via `broadcast.spec.ts` page-content tests — Fix: create `frontend/e2e/broadcast-navigation.spec.ts` covering sidebar links, flag hide/show, deep-link — Effort: S
- [LOW] `/broadcast/schedule` absent from mobile nav — `frontend/src/components/layout/AppShell.tsx` / `MobileNav.tsx` — desktop sidebar has "Scheduled Broadcasts" entry but mobile does not — Fix: add entry + flag filter to `AppShell.tsx` mobile nav groups — Effort: S
- [LOW] Active-route highlighting missing for `/live/:sessionId` — `frontend/src/components/layout/Sidebar.tsx` — Broadcast sidebar entry does not highlight when on player page — Fix: extend `isActive` check to also match `location.pathname.startsWith("/live")` — Effort: S
