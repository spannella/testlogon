# Master Dependency Graph & Merge Order

**280 tickets** across **40 feature areas** | **9 merge waves** (0–8) | **41 cross-area dependencies**

Generated from the `## Dependencies & Merge Safety` sections of all ticket specs.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Merge Waves (Topological Order)](#2-merge-waves)
3. [Critical Paths](#3-critical-paths)
4. [Foundation Tickets](#4-foundation-tickets)
5. [Cross-Area Dependencies](#5-cross-area-dependencies)
6. [Dependency Cycles](#6-dependency-cycles)
7. [Per-Area Dependency Chains](#7-per-area-dependency-chains)
8. [Independent Tickets (No Upstream Deps)](#8-independent-tickets)
9. [Full Topological Order](#9-full-topological-order)
10. [Merge Strategy Summary](#10-merge-strategy-summary)

---

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| Total tickets | 280 |
| Feature areas | 40 |
| Merge waves (levels) | 9 (0–8) |
| Root tickets (wave 0, no upstream deps) | 101 |
| Leaf tickets (no downstream deps) | 162 |
| Cross-area dependencies | 41 |
| Dependency cycles | 1 (NOTIFY-001 ↔ PLATFORM-010, broken as soft dep) |
| Deepest chain | 9 levels (INFRA-001 → … → AGENT-012) |
| Most depended-on ticket | VOD-001 (17 downstream tickets) |
| Most dependent ticket | AGENT-012 (10 upstream dependencies) |

**Strategy distribution:**

- **Independent**: 117 tickets
- **Sequential**: 133 tickets
- **Feature-Flag-Gated**: 16 tickets
- **Parallel**: 5 tickets
- **Unknown**: 9 tickets

---

## 2. Merge Waves

Tickets at the same wave level have no dependencies on each other and can be merged in parallel.
Each wave must complete before the next wave's tickets can safely merge.

### Wave 0 — 101 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| ADMIN | ADMIN-001, ADMIN-002, ADMIN-003 | unknown |
| ADS | ADS-001 | independent |
| AFFILIATE | AFFILIATE-001 | independent |
| AGENT | AGENT-001 | independent |
| BCAST | BCAST-001 | independent |
| BILLING | BILLING-002, BILLING-003 | independent |
| BOT | BOT-001 | independent |
| CALL | CALL-001 | independent |
| CREATOR | CREATOR-002, CREATOR-003, CREATOR-004 | independent |
| DELEGATE | DELEGATE-001 | independent |
| ENGAGE | ENGAGE-001, ENGAGE-002, ENGAGE-003, ENGAGE-004, ENGAGE-005 | independent |
| ENTERPRISE | ENTERPRISE-001, ENTERPRISE-004, ENTERPRISE-005 | independent |
| FEED | FEED-001, FEED-002, FEED-003, FEED-004, FEED-005, FEED-006, FEED-007, FEED-009 | independent |
| FILES | FILES-001 | independent |
| FIN | FIN-001, FIN-002, FIN-003, FIN-004, FIN-005, FIN-006, FIN-007, FIN-008, FIN-009, FIN-010, FIN-011, FIN-012, FIN-013, FIN-014, FIN-015, FIN-018 | feature-flag-gated, independent |
| GEO | GEO-001 | feature-flag-gated |
| GROUP | GROUP-001 | independent |
| INFRA | INFRA-001 | independent |
| INTEG | INTEG-001 | independent |
| KYC | KYC-001 | independent |
| LCOM | LCOM-001 | independent |
| LICENSE | LICENSE-001 | independent |
| MEDIA | MEDIA-001, MEDIA-002 | independent |
| MOD | MOD-002, MOD-003 | independent |
| MON | MON-002 | independent |
| MSG | MSG-001, MSG-002, MSG-003, MSG-004, MSG-005, MSG-006, MSG-008, MSG-009, MSG-010, MSG-012 | independent |
| PLATFORM | PLATFORM-001, PLATFORM-002, PLATFORM-003, PLATFORM-004, PLATFORM-005, PLATFORM-006, PLATFORM-008, PLATFORM-009, PLATFORM-010, PLATFORM-013, PLATFORM-014, PLATFORM-015, PLATFORM-019 | feature-flag-gated, independent |
| PRIVACY | PRIVACY-001 | independent |
| PROMO | PROMO-001 | independent |
| PWA | PWA-001 | independent |
| SCHED | SCHED-001 | independent |
| SHOP | SHOP-001, SHOP-004 | independent |
| SOC | SOC-001 | independent |
| SOCIAL | SOCIAL-001, SOCIAL-003, SOCIAL-004, SOCIAL-006 | independent, unknown |
| SYND | SYND-001 | unknown |
| UX | UX-001, UX-002, UX-003, UX-004, UX-005 | independent |
| VOD | VOD-001 | unknown |

### Wave 1 — 56 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| ADS | ADS-002, ADS-003 | sequential |
| BCAST | BCAST-002, BCAST-003, BCAST-006, BCAST-007, BCAST-009 | independent, parallel |
| BILLING | BILLING-001 | independent |
| BOT | BOT-002, BOT-004 | sequential |
| CALL | CALL-002, CALL-007 | independent, sequential |
| DELEGATE | DELEGATE-002, DELEGATE-003, DELEGATE-004 | sequential |
| ENTERPRISE | ENTERPRISE-002, ENTERPRISE-003 | sequential |
| FEED | FEED-008 | sequential |
| FIN | FIN-016, FIN-017 | sequential |
| GROUP | GROUP-002, GROUP-004 | sequential |
| INFRA | INFRA-002, INFRA-010 | sequential |
| KYC | KYC-002, KYC-003, KYC-005, KYC-007 | sequential |
| LCOM | LCOM-002, LCOM-003 | sequential |
| LICENSE | LICENSE-002 | independent |
| MOD | MOD-001 | sequential |
| MON | MON-001, MON-003 | independent, sequential |
| MSG | MSG-007 | sequential |
| NOTIFY | NOTIFY-001 | independent |
| PLATFORM | PLATFORM-007, PLATFORM-016, PLATFORM-018 | feature-flag-gated, independent, sequential |
| PWA | PWA-002 | sequential |
| SHOP | SHOP-002, SHOP-003 | feature-flag-gated, sequential |
| SOC | SOC-002, SOC-003, SOC-005 | sequential |
| SOCIAL | SOCIAL-002, SOCIAL-007 | sequential, unknown |
| SYND | SYND-002, SYND-004, SYND-005 | sequential, unknown |
| VOD | VOD-002, VOD-010, VOD-012, VOD-013, VOD-014, VOD-015 | independent, sequential |

### Wave 2 — 39 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| ADS | ADS-004 | sequential |
| ANALYTICS | ANALYTICS-001 | independent |
| BCAST | BCAST-004, BCAST-005, BCAST-008, BCAST-010, BCAST-016 | independent, parallel, sequential |
| BOT | BOT-003 | sequential |
| CALL | CALL-003, CALL-008, CALL-011, CALL-012, CALL-014 | independent, sequential |
| DELEGATE | DELEGATE-005 | sequential |
| GROUP | GROUP-003 | sequential |
| INFRA | INFRA-003, INFRA-004, INFRA-006, INFRA-011 | sequential |
| KYC | KYC-004, KYC-006, KYC-010 | sequential |
| LCOM | LCOM-004 | sequential |
| LICENSE | LICENSE-003, LICENSE-004, LICENSE-006 | sequential |
| MON | MON-004, MON-005 | sequential |
| MSG | MSG-011 | sequential |
| PLATFORM | PLATFORM-011 | independent |
| PWA | PWA-003 | sequential |
| SOC | SOC-004 | sequential |
| SOCIAL | SOCIAL-005 | independent |
| SYND | SYND-003, SYND-006 | sequential, unknown |
| VOD | VOD-003, VOD-008, VOD-016, VOD-020 | sequential |

### Wave 3 — 29 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| ADS | ADS-005, ADS-006, ADS-007, ADS-015 | sequential |
| AGENT | AGENT-002 | sequential |
| ANALYTICS | ANALYTICS-002 | sequential |
| BCAST | BCAST-011, BCAST-012, BCAST-013, BCAST-014 | independent, parallel |
| CALL | CALL-004, CALL-006, CALL-009 | sequential |
| CREATOR | CREATOR-001, CREATOR-005 | independent |
| INFRA | INFRA-005, INFRA-007, INFRA-008, INFRA-009 | feature-flag-gated, sequential |
| KYC | KYC-008, KYC-018 | feature-flag-gated, sequential |
| LICENSE | LICENSE-005 | sequential |
| PLATFORM | PLATFORM-012 | sequential |
| PWA | PWA-004 | sequential |
| VOD | VOD-004, VOD-009, VOD-018, VOD-019, VOD-021 | parallel, sequential |

### Wave 4 — 18 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| ADS | ADS-008, ADS-009, ADS-010, ADS-012, ADS-014, ADS-016 | feature-flag-gated, sequential |
| AGENT | AGENT-003 | sequential |
| BCAST | BCAST-015 | sequential |
| CALL | CALL-005, CALL-010 | sequential |
| INFRA | INFRA-012 | sequential |
| KYC | KYC-009, KYC-012, KYC-019 | feature-flag-gated, sequential |
| PWA | PWA-005 | sequential |
| VOD | VOD-005, VOD-011, VOD-017 | sequential |

### Wave 5 — 18 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| ADS | ADS-011, ADS-013, ADS-017, ADS-018, ADS-019 | sequential |
| AGENT | AGENT-004, AGENT-005, AGENT-006 | sequential |
| CALL | CALL-013 | sequential |
| DISC | DISC-001 | independent |
| KYC | KYC-011, KYC-013, KYC-015, KYC-017, KYC-022, KYC-023, KYC-024 | feature-flag-gated, independent, sequential |
| VOD | VOD-006 | independent |

### Wave 6 — 10 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| AGENT | AGENT-007, AGENT-008, AGENT-010, AGENT-011 | sequential |
| KYC | KYC-014, KYC-016, KYC-020, KYC-021 | feature-flag-gated, sequential |
| SOC | SOC-006 | independent |
| VOD | VOD-007 | sequential |

### Wave 7 — 8 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| AGENT | AGENT-009, AGENT-013, AGENT-014, AGENT-015, AGENT-016, AGENT-017, AGENT-018 | sequential |
| PLATFORM | PLATFORM-017 | feature-flag-gated |

### Wave 8 — 1 tickets

| Area | Tickets | Strategy |
|------|---------|----------|
| AGENT | AGENT-012 | sequential |

---

## 3. Critical Paths

The longest dependency chains determine the minimum time to complete all work,
assuming unlimited parallelism within each wave.

| # | Depth | Path |
|---|-------|------|
| 1 | 9 | INFRA-001 → INFRA-002 → INFRA-003 → AGENT-002 → AGENT-003 → AGENT-004 → AGENT-008 → AGENT-009 → AGENT-012 |
| 2 | 8 | MEDIA-002 → VOD-002 → VOD-003 → VOD-004 → VOD-005 → VOD-006 → SOC-006 → PLATFORM-017 |
| 3 | 8 | VOD-001 → VOD-002 → VOD-003 → VOD-004 → VOD-005 → VOD-006 → SOC-006 → PLATFORM-017 |
| 4 | 7 | AGENT-001 → AGENT-002 → AGENT-003 → AGENT-004 → AGENT-008 → AGENT-009 → AGENT-012 |
| 5 | 7 | KYC-001 → KYC-002 → KYC-004 → KYC-008 → KYC-009 → KYC-011 → KYC-016 |
| 6 | 6 | ADS-001 → ADS-002 → ADS-004 → ADS-007 → ADS-008 → ADS-011 |
| 7 | 6 | CALL-001 → CALL-002 → CALL-003 → CALL-004 → CALL-005 → CALL-013 |
| 8 | 5 | BCAST-001 → BCAST-002 → BCAST-005 → BCAST-012 → BCAST-015 |
| 9 | 5 | MEDIA-001 → MON-001 → MON-005 → SOC-006 → PLATFORM-017 |
| 10 | 5 | PWA-001 → PWA-002 → PWA-003 → PWA-004 → PWA-005 |
| 11 | 4 | LICENSE-001 → LICENSE-002 → LICENSE-003 → LICENSE-005 |
| 12 | 4 | MON-002 → MON-003 → ANALYTICS-001 → ANALYTICS-002 |
| 13 | 4 | SOC-001 → SOC-002 → BCAST-010 → CREATOR-005 |
| 14 | 4 | SOCIAL-003 → SOC-005 → SOC-006 → PLATFORM-017 |
| 15 | 3 | BOT-001 → BOT-002 → BOT-003 |
| 16 | 3 | DELEGATE-001 → DELEGATE-002 → DELEGATE-005 |
| 17 | 3 | GROUP-001 → GROUP-004 → GROUP-003 |
| 18 | 3 | LCOM-001 → LCOM-003 → LCOM-004 |
| 19 | 3 | MSG-006 → MSG-007 → MSG-011 |
| 20 | 3 | SYND-001 → SYND-002 → SYND-003 |

**Longest chain**: 9 steps — this is the minimum number of sequential merge waves
needed for the deepest feature (AGENT orchestration platform).

---

## 4. Foundation Tickets

These tickets have the most downstream dependents. Breaking changes or delays here
cascade widely. Prioritize review and stability for these.

| Ticket | Downstream Count | Direct Dependents |
|--------|-----------------|-------------------|
| **VOD-001** | 17 | VOD-002, VOD-003, VOD-006, VOD-008, VOD-009, VOD-010, VOD-011, VOD-012, … (+9 more) |
| **AGENT-002** | 15 | AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008, AGENT-009, AGENT-010, AGENT-011, … (+7 more) |
| **AGENT-003** | 15 | AGENT-004, AGENT-005, AGENT-006, AGENT-007, AGENT-008, AGENT-009, AGENT-010, AGENT-011, … (+7 more) |
| **ADS-001** | 14 | ADS-002, ADS-003, ADS-004, ADS-005, ADS-007, ADS-008, ADS-011, ADS-012, … (+6 more) |
| **AGENT-001** | 13 | AGENT-002, AGENT-004, AGENT-008, AGENT-009, AGENT-010, AGENT-011, AGENT-012, AGENT-013, … (+5 more) |
| **KYC-001** | 13 | KYC-002, KYC-003, KYC-004, KYC-005, KYC-006, KYC-007, KYC-008, KYC-009, … (+5 more) |
| **AGENT-006** | 12 | AGENT-007, AGENT-008, AGENT-009, AGENT-010, AGENT-011, AGENT-012, AGENT-013, AGENT-014, … (+4 more) |
| **AGENT-004** | 11 | AGENT-008, AGENT-009, AGENT-010, AGENT-011, AGENT-012, AGENT-013, AGENT-014, AGENT-015, … (+3 more) |
| **AGENT-005** | 11 | AGENT-008, AGENT-009, AGENT-010, AGENT-011, AGENT-012, AGENT-013, AGENT-014, AGENT-015, … (+3 more) |
| **ADS-004** | 11 | ADS-005, ADS-006, ADS-007, ADS-008, ADS-009, ADS-010, ADS-014, ADS-015, … (+3 more) |
| **SOC-001** | 9 | DISC-001, PLATFORM-017, SOC-002, SOC-003, SOC-004, SOC-005, SOC-006, SOCIAL-002, … (+1 more) |
| **ADS-007** | 8 | ADS-008, ADS-010, ADS-012, ADS-013, ADS-014, ADS-016, ADS-017, ADS-018 |
| **MON-002** | 8 | BCAST-012, BCAST-013, BCAST-015, BILLING-001, CALL-011, MON-003, MON-004, SOCIAL-005 |
| **CALL-002** | 8 | BCAST-016, CALL-003, CALL-006, CALL-008, CALL-009, CALL-011, CALL-012, CALL-013 |
| **BCAST-001** | 8 | BCAST-002, BCAST-003, BCAST-004, BCAST-005, BCAST-006, BCAST-007, BCAST-009, BCAST-016 |
| **ADS-002** | 7 | ADS-004, ADS-005, ADS-006, ADS-011, ADS-015, ADS-017, ADS-018 |
| **AGENT-007** | 6 | AGENT-013, AGENT-014, AGENT-015, AGENT-016, AGENT-017, AGENT-018 |
| **INFRA-003** | 6 | AGENT-002, INFRA-005, INFRA-007, INFRA-008, INFRA-009, INFRA-012 |
| **INFRA-004** | 6 | AGENT-002, INFRA-005, INFRA-007, INFRA-008, INFRA-009, INFRA-012 |
| **INFRA-001** | 6 | INFRA-002, INFRA-003, INFRA-004, INFRA-006, INFRA-010, INFRA-011 |
| **KYC-009** | 6 | KYC-011, KYC-013, KYC-015, KYC-016, KYC-017, KYC-022 |
| **SYND-001** | 5 | SYND-002, SYND-003, SYND-004, SYND-005, SYND-006 |
| **KYC-008** | 5 | KYC-009, KYC-012, KYC-016, KYC-019, KYC-024 |
| **BCAST-005** | 5 | BCAST-011, BCAST-012, BCAST-013, BCAST-014, BCAST-015 |
| **VOD-008** | 5 | VOD-009, VOD-011, VOD-018, VOD-019, VOD-021 |
| **KYC-002** | 5 | KYC-004, KYC-006, KYC-008, KYC-010, KYC-022 |
| **ADS-008** | 4 | ADS-011, ADS-013, ADS-017, ADS-018 |
| **CALL-001** | 4 | BCAST-011, CALL-002, CALL-007, CALL-014 |
| **LICENSE-002** | 4 | LICENSE-003, LICENSE-004, LICENSE-005, LICENSE-006 |
| **DELEGATE-001** | 4 | DELEGATE-002, DELEGATE-003, DELEGATE-004, DELEGATE-005 |

---

## 5. Cross-Area Dependencies

These are dependencies that cross feature-area boundaries. They require coordination
between teams and are higher risk for merge conflicts.

| Ticket | Depends On | Areas |
|--------|-----------|-------|
| ADS-015 | AFFILIATE-001 | ADS → AFFILIATE |
| AGENT-002 | INFRA-003 | AGENT → INFRA |
| AGENT-002 | INFRA-004 | AGENT → INFRA |
| ANALYTICS-001 | MON-003 | ANALYTICS → MON |
| BCAST-010 | SOC-002 | BCAST → SOC |
| BCAST-011 | CALL-001 | BCAST → CALL |
| BCAST-012 | MON-002 | BCAST → MON |
| BCAST-013 | MON-002 | BCAST → MON |
| BCAST-015 | MON-002 | BCAST → MON |
| BCAST-016 | CALL-002 | BCAST → CALL |
| BILLING-001 | MON-002 | BILLING → MON |
| CALL-011 | MON-002 | CALL → MON |
| CALL-014 | MSG-002 | CALL → MSG |
| CREATOR-001 | BCAST-016 | CREATOR → BCAST |
| CREATOR-005 | BCAST-010 | CREATOR → BCAST |
| DISC-001 | SOC-001 | DISC → SOC |
| DISC-001 | VOD-017 | DISC → VOD |
| MOD-001 | MEDIA-001 | MOD → MEDIA |
| MON-001 | MEDIA-001 | MON → MEDIA |
| NOTIFY-001 | PLATFORM-010 | NOTIFY → PLATFORM |
| PLATFORM-010 | NOTIFY-001 | PLATFORM → NOTIFY |
| PLATFORM-011 | SOC-003 | PLATFORM → SOC |
| PLATFORM-012 | SOC-004 | PLATFORM → SOC |
| PLATFORM-017 | MON-005 | PLATFORM → MON |
| PLATFORM-017 | SOC-001 | PLATFORM → SOC |
| PLATFORM-017 | SOC-005 | PLATFORM → SOC |
| PLATFORM-017 | SOC-006 | PLATFORM → SOC |
| PLATFORM-017 | VOD-006 | PLATFORM → VOD |
| PLATFORM-018 | PRIVACY-001 | PLATFORM → PRIVACY |
| SHOP-002 | PROMO-001 | SHOP → PROMO |
| SHOP-003 | PLATFORM-006 | SHOP → PLATFORM |
| SOC-004 | NOTIFY-001 | SOC → NOTIFY |
| SOC-005 | SOCIAL-003 | SOC → SOCIAL |
| SOC-006 | MON-005 | SOC → MON |
| SOC-006 | VOD-006 | SOC → VOD |
| SOCIAL-002 | SOC-001 | SOCIAL → SOC |
| SOCIAL-005 | MON-002 | SOCIAL → MON |
| SOCIAL-005 | MON-003 | SOCIAL → MON |
| SOCIAL-007 | SOC-001 | SOCIAL → SOC |
| VOD-002 | MEDIA-002 | VOD → MEDIA |
| VOD-004 | MEDIA-002 | VOD → MEDIA |

---

## 6. Dependency Cycles

One dependency cycle was detected and resolved:

```
NOTIFY-001 ←→ PLATFORM-010
  │
  ├── NOTIFY-001 depends on PLATFORM-010 (notification routing needs platform webhooks)
  └── PLATFORM-010 depends on NOTIFY-001 (webhooks need notification delivery)
```

**Resolution**: Break PLATFORM-010 → NOTIFY-001 into a soft dependency.
Merge NOTIFY-001 first with a stub/feature-flag for the PLATFORM-010 integration,
then merge PLATFORM-010, then update NOTIFY-001 to wire in the real integration.

**Downstream impact**: SOC-004 (depends on NOTIFY-001), PLATFORM-012 (depends on SOC-004),
PLATFORM-016 (depends on PLATFORM-010) are all unblocked once the cycle is broken.

---

## 7. Per-Area Dependency Chains

### ADMIN (3 tickets)

- **ADMIN-001** (wave 0, unknown)
- **ADMIN-002** (wave 0, unknown)
- **ADMIN-003** (wave 0, unknown)

### ADS (19 tickets)

- **ADS-001** (wave 0, independent)
- **ADS-002** (wave 1, sequential) ← ADS-001
- **ADS-003** (wave 1, sequential) ← ADS-001
- **ADS-004** (wave 2, sequential) ← ADS-001, ADS-002, ADS-003
- **ADS-005** (wave 3, sequential) ← ADS-001, ADS-002, ADS-004
- **ADS-006** (wave 3, sequential) ← ADS-002, ADS-004
- **ADS-007** (wave 3, sequential) ← ADS-001, ADS-004
- **ADS-008** (wave 4, sequential) ← ADS-001, ADS-004, ADS-007
- **ADS-009** (wave 4, feature-flag-gated) ← ADS-004, ADS-005
- **ADS-010** (wave 4, sequential) ← ADS-003, ADS-004, ADS-007
- **ADS-011** (wave 5, sequential) ← ADS-001, ADS-002, ADS-008
- **ADS-012** (wave 4, sequential) ← ADS-001, ADS-005, ADS-007
- **ADS-013** (wave 5, sequential) ← ADS-001, ADS-007, ADS-008
- **ADS-014** (wave 4, sequential) ← ADS-001, ADS-004, ADS-007
- **ADS-015** (wave 3, sequential) ← ADS-002, ADS-004 ← [AFFILIATE-001]
- **ADS-016** (wave 4, sequential) ← ADS-001, ADS-004, ADS-007
- **ADS-017** (wave 5, sequential) ← ADS-001, ADS-002, ADS-004, ADS-007, ADS-008
- **ADS-018** (wave 5, sequential) ← ADS-001, ADS-002, ADS-004, ADS-007, ADS-008, ADS-014
- **ADS-019** (wave 5, sequential) ← ADS-001, ADS-010

```
ADS-001
  └── ADS-002
    └── ADS-004
      └── ADS-005
        └── ADS-009
        └── ADS-012
      └── ADS-006
      └── ADS-007
        └── ADS-008
          └── ADS-011
          └── ADS-013
          └── ADS-017
          └── ADS-018
        └── ADS-010
          └── ADS-019
        └── ADS-014
        └── ADS-016
      └── ADS-015
  └── ADS-003
```

### AFFILIATE (1 ticket)

- **AFFILIATE-001** — independent

### AGENT (18 tickets)

- **AGENT-001** (wave 0, independent)
- **AGENT-002** (wave 3, sequential) ← AGENT-001 ← [INFRA-003, INFRA-004]
- **AGENT-003** (wave 4, sequential) ← AGENT-002
- **AGENT-004** (wave 5, sequential) ← AGENT-001, AGENT-002, AGENT-003
- **AGENT-005** (wave 5, sequential) ← AGENT-002, AGENT-003
- **AGENT-006** (wave 5, sequential) ← AGENT-002, AGENT-003
- **AGENT-007** (wave 6, sequential) ← AGENT-003, AGENT-006
- **AGENT-008** (wave 6, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006
- **AGENT-009** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008
- **AGENT-010** (wave 6, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006
- **AGENT-011** (wave 6, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006
- **AGENT-012** (wave 8, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008, AGENT-009, AGENT-010, AGENT-011
- **AGENT-013** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- **AGENT-014** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- **AGENT-015** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- **AGENT-016** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- **AGENT-017** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- **AGENT-018** (wave 7, sequential) ← AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007

```
AGENT-001
  └── AGENT-002
    └── AGENT-003
      └── AGENT-004
        └── AGENT-008
          └── AGENT-009
            └── AGENT-012
        └── AGENT-010
        └── AGENT-011
        └── AGENT-013
        └── AGENT-014
        └── AGENT-015
        └── AGENT-016
        └── AGENT-017
        └── AGENT-018
      └── AGENT-005
      └── AGENT-006
        └── AGENT-007
```

### ANALYTICS (2 tickets)

- **ANALYTICS-001** (wave 2, independent) ← [MON-003]
- **ANALYTICS-002** (wave 3, sequential) ← ANALYTICS-001

```
ANALYTICS-001
  └── ANALYTICS-002
```

### BCAST (16 tickets)

- **BCAST-001** (wave 0, independent)
- **BCAST-002** (wave 1, parallel) ← BCAST-001
- **BCAST-003** (wave 1, independent) ← BCAST-001
- **BCAST-004** (wave 2, parallel) ← BCAST-001, BCAST-002
- **BCAST-005** (wave 2, independent) ← BCAST-001, BCAST-002
- **BCAST-006** (wave 1, independent) ← BCAST-001
- **BCAST-007** (wave 1, independent) ← BCAST-001
- **BCAST-008** (wave 2, sequential) ← BCAST-006
- **BCAST-009** (wave 1, independent) ← BCAST-001
- **BCAST-010** (wave 2, sequential) ← BCAST-009 ← [SOC-002]
- **BCAST-011** (wave 3, independent) ← BCAST-005 ← [CALL-001]
- **BCAST-012** (wave 3, parallel) ← BCAST-005 ← [MON-002]
- **BCAST-013** (wave 3, parallel) ← BCAST-005 ← [MON-002]
- **BCAST-014** (wave 3, independent) ← BCAST-005
- **BCAST-015** (wave 4, sequential) ← BCAST-005, BCAST-012 ← [MON-002]
- **BCAST-016** (wave 2, independent) ← BCAST-001, BCAST-003 ← [CALL-002]

```
BCAST-001
  └── BCAST-002
    └── BCAST-004
    └── BCAST-005
      └── BCAST-011
      └── BCAST-012
        └── BCAST-015
      └── BCAST-013
      └── BCAST-014
  └── BCAST-003
    └── BCAST-016
  └── BCAST-006
    └── BCAST-008
  └── BCAST-007
  └── BCAST-009
    └── BCAST-010
```

### BILLING (3 tickets)

- **BILLING-001** (wave 1, independent) ← [MON-002]
- **BILLING-002** (wave 0, independent)
- **BILLING-003** (wave 0, independent)

### BOT (4 tickets)

- **BOT-001** (wave 0, independent)
- **BOT-002** (wave 1, sequential) ← BOT-001
- **BOT-003** (wave 2, sequential) ← BOT-001, BOT-002
- **BOT-004** (wave 1, sequential) ← BOT-001

```
BOT-001
  └── BOT-002
    └── BOT-003
  └── BOT-004
```

### CALL (14 tickets)

- **CALL-001** (wave 0, independent)
- **CALL-002** (wave 1, sequential) ← CALL-001
- **CALL-003** (wave 2, sequential) ← CALL-002
- **CALL-004** (wave 3, sequential) ← CALL-003
- **CALL-005** (wave 4, sequential) ← CALL-003, CALL-004
- **CALL-006** (wave 3, sequential) ← CALL-002, CALL-003
- **CALL-007** (wave 1, independent) ← CALL-001
- **CALL-008** (wave 2, sequential) ← CALL-002
- **CALL-009** (wave 3, sequential) ← CALL-002, CALL-008
- **CALL-010** (wave 4, sequential) ← CALL-009
- **CALL-011** (wave 2, independent) ← CALL-002 ← [MON-002]
- **CALL-012** (wave 2, independent) ← CALL-002
- **CALL-013** (wave 5, sequential) ← CALL-002, CALL-005, CALL-012
- **CALL-014** (wave 2, independent) ← CALL-001, CALL-007 ← [MSG-002]

```
CALL-001
  └── CALL-002
    └── CALL-003
      └── CALL-004
        └── CALL-005
          └── CALL-013
      └── CALL-006
    └── CALL-008
      └── CALL-009
        └── CALL-010
    └── CALL-011
    └── CALL-012
  └── CALL-007
    └── CALL-014
```

### CREATOR (5 tickets)

- **CREATOR-001** (wave 3, independent) ← [BCAST-016]
- **CREATOR-002** (wave 0, independent)
- **CREATOR-003** (wave 0, independent)
- **CREATOR-004** (wave 0, independent)
- **CREATOR-005** (wave 3, independent) ← [BCAST-010]

### DELEGATE (5 tickets)

- **DELEGATE-001** (wave 0, independent)
- **DELEGATE-002** (wave 1, sequential) ← DELEGATE-001
- **DELEGATE-003** (wave 1, sequential) ← DELEGATE-001
- **DELEGATE-004** (wave 1, sequential) ← DELEGATE-001
- **DELEGATE-005** (wave 2, sequential) ← DELEGATE-001, DELEGATE-002, DELEGATE-003, DELEGATE-004

```
DELEGATE-001
  └── DELEGATE-002
    └── DELEGATE-005
  └── DELEGATE-003
  └── DELEGATE-004
```

### DISC (1 ticket)

- **DISC-001** — independent
  - Cross-area deps: SOC-001, VOD-017

### ENGAGE (5 tickets)

- **ENGAGE-001** (wave 0, independent)
- **ENGAGE-002** (wave 0, independent)
- **ENGAGE-003** (wave 0, independent)
- **ENGAGE-004** (wave 0, independent)
- **ENGAGE-005** (wave 0, independent)

### ENTERPRISE (5 tickets)

- **ENTERPRISE-001** (wave 0, independent)
- **ENTERPRISE-002** (wave 1, sequential) ← ENTERPRISE-001
- **ENTERPRISE-003** (wave 1, sequential) ← ENTERPRISE-001
- **ENTERPRISE-004** (wave 0, independent)
- **ENTERPRISE-005** (wave 0, independent)

```
ENTERPRISE-001
  └── ENTERPRISE-002
  └── ENTERPRISE-003
ENTERPRISE-004
ENTERPRISE-005
```

### FEED (9 tickets)

- **FEED-001** (wave 0, independent)
- **FEED-002** (wave 0, independent)
- **FEED-003** (wave 0, independent)
- **FEED-004** (wave 0, independent)
- **FEED-005** (wave 0, independent)
- **FEED-006** (wave 0, independent)
- **FEED-007** (wave 0, independent)
- **FEED-008** (wave 1, sequential) ← FEED-004, FEED-005
- **FEED-009** (wave 0, independent)

```
FEED-001
FEED-002
FEED-003
FEED-004
  └── FEED-008
FEED-005
FEED-006
FEED-007
FEED-009
```

### FILES (1 ticket)

- **FILES-001** — independent

### FIN (18 tickets)

- **FIN-001** (wave 0, independent)
- **FIN-002** (wave 0, independent)
- **FIN-003** (wave 0, independent)
- **FIN-004** (wave 0, independent)
- **FIN-005** (wave 0, feature-flag-gated)
- **FIN-006** (wave 0, independent)
- **FIN-007** (wave 0, independent)
- **FIN-008** (wave 0, independent)
- **FIN-009** (wave 0, independent)
- **FIN-010** (wave 0, independent)
- **FIN-011** (wave 0, independent)
- **FIN-012** (wave 0, independent)
- **FIN-013** (wave 0, independent)
- **FIN-014** (wave 0, independent)
- **FIN-015** (wave 0, feature-flag-gated)
- **FIN-016** (wave 1, sequential) ← FIN-013
- **FIN-017** (wave 1, sequential) ← FIN-015
- **FIN-018** (wave 0, feature-flag-gated)

```
FIN-001
FIN-002
FIN-003
FIN-004
FIN-005
FIN-006
FIN-007
FIN-008
FIN-009
FIN-010
FIN-011
FIN-012
FIN-013
  └── FIN-016
FIN-014
FIN-015
  └── FIN-017
FIN-018
```

### GEO (1 ticket)

- **GEO-001** — independent

### GROUP (4 tickets)

- **GROUP-001** (wave 0, independent)
- **GROUP-002** (wave 1, sequential) ← GROUP-001
- **GROUP-003** (wave 2, sequential) ← GROUP-001, GROUP-004
- **GROUP-004** (wave 1, sequential) ← GROUP-001

```
GROUP-001
  └── GROUP-002
  └── GROUP-003
  └── GROUP-004
```

### INFRA (12 tickets)

- **INFRA-001** (wave 0, independent)
- **INFRA-002** (wave 1, sequential) ← INFRA-001
- **INFRA-003** (wave 2, sequential) ← INFRA-001, INFRA-002
- **INFRA-004** (wave 2, sequential) ← INFRA-001, INFRA-002
- **INFRA-005** (wave 3, sequential) ← INFRA-003, INFRA-004
- **INFRA-006** (wave 2, sequential) ← INFRA-001, INFRA-002
- **INFRA-007** (wave 3, feature-flag-gated) ← INFRA-003, INFRA-004
- **INFRA-008** (wave 3, sequential) ← INFRA-003, INFRA-004
- **INFRA-009** (wave 3, sequential) ← INFRA-003, INFRA-004
- **INFRA-010** (wave 1, sequential) ← INFRA-001
- **INFRA-011** (wave 2, sequential) ← INFRA-001, INFRA-002
- **INFRA-012** (wave 4, sequential) ← INFRA-003, INFRA-004, INFRA-005

```
INFRA-001
  └── INFRA-002
    └── INFRA-003
      └── INFRA-005
        └── INFRA-012
      └── INFRA-007
      └── INFRA-008
      └── INFRA-009
    └── INFRA-004
    └── INFRA-006
    └── INFRA-011
  └── INFRA-010
```

### INTEG (1 ticket)

- **INTEG-001** — independent

### KYC (24 tickets)

- **KYC-001** (wave 0, independent)
- **KYC-002** (wave 1, sequential) ← KYC-001
- **KYC-003** (wave 1, sequential) ← KYC-001
- **KYC-004** (wave 2, sequential) ← KYC-001, KYC-002
- **KYC-005** (wave 1, sequential) ← KYC-001
- **KYC-006** (wave 2, sequential) ← KYC-001, KYC-002
- **KYC-007** (wave 1, sequential) ← KYC-001
- **KYC-008** (wave 3, sequential) ← KYC-001, KYC-002, KYC-004, KYC-005, KYC-006
- **KYC-009** (wave 4, sequential) ← KYC-001, KYC-008
- **KYC-010** (wave 2, sequential) ← KYC-002
- **KYC-011** (wave 5, sequential) ← KYC-001, KYC-009
- **KYC-012** (wave 4, sequential) ← KYC-001, KYC-006, KYC-008
- **KYC-013** (wave 5, sequential) ← KYC-009, KYC-010
- **KYC-014** (wave 6, sequential) ← KYC-010, KYC-013
- **KYC-015** (wave 5, sequential) ← KYC-006, KYC-009
- **KYC-016** (wave 6, sequential) ← KYC-006, KYC-008, KYC-009, KYC-011
- **KYC-017** (wave 5, sequential) ← KYC-007, KYC-009
- **KYC-018** (wave 3, feature-flag-gated) ← KYC-004
- **KYC-019** (wave 4, feature-flag-gated) ← KYC-001, KYC-008
- **KYC-020** (wave 6, feature-flag-gated) ← KYC-013, KYC-017
- **KYC-021** (wave 6, feature-flag-gated) ← KYC-011
- **KYC-022** (wave 5, feature-flag-gated) ← KYC-002, KYC-009
- **KYC-023** (wave 5, feature-flag-gated) ← KYC-001, KYC-012
- **KYC-024** (wave 5, independent) ← KYC-001, KYC-008, KYC-012

```
KYC-001
  └── KYC-002
    └── KYC-004
      └── KYC-008
        └── KYC-009
          └── KYC-011
            └── KYC-016
            └── KYC-021
          └── KYC-013
            └── KYC-014
            └── KYC-020
          └── KYC-015
          └── KYC-017
          └── KYC-022
        └── KYC-012
          └── KYC-023
          └── KYC-024
        └── KYC-019
      └── KYC-018
    └── KYC-006
    └── KYC-010
  └── KYC-003
  └── KYC-005
  └── KYC-007
```

### LCOM (4 tickets)

- **LCOM-001** (wave 0, independent)
- **LCOM-002** (wave 1, sequential) ← LCOM-001
- **LCOM-003** (wave 1, sequential) ← LCOM-001
- **LCOM-004** (wave 2, sequential) ← LCOM-001, LCOM-003

```
LCOM-001
  └── LCOM-002
  └── LCOM-003
    └── LCOM-004
```

### LICENSE (6 tickets)

- **LICENSE-001** (wave 0, independent)
- **LICENSE-002** (wave 1, independent) ← LICENSE-001
- **LICENSE-003** (wave 2, sequential) ← LICENSE-002
- **LICENSE-004** (wave 2, sequential) ← LICENSE-002
- **LICENSE-005** (wave 3, sequential) ← LICENSE-002, LICENSE-003
- **LICENSE-006** (wave 2, sequential) ← LICENSE-001, LICENSE-002

```
LICENSE-001
  └── LICENSE-002
    └── LICENSE-003
      └── LICENSE-005
    └── LICENSE-004
    └── LICENSE-006
```

### MEDIA (2 tickets)

- **MEDIA-001** (wave 0, independent)
- **MEDIA-002** (wave 0, independent)

### MOD (3 tickets)

- **MOD-001** (wave 1, sequential) ← [MEDIA-001]
- **MOD-002** (wave 0, independent)
- **MOD-003** (wave 0, independent)

### MON (5 tickets)

- **MON-001** (wave 1, independent) ← [MEDIA-001]
- **MON-002** (wave 0, independent)
- **MON-003** (wave 1, sequential) ← MON-002
- **MON-004** (wave 2, sequential) ← MON-002, MON-003
- **MON-005** (wave 2, sequential) ← MON-001

```
MON-001
  └── MON-005
MON-002
  └── MON-003
    └── MON-004
```

### MSG (12 tickets)

- **MSG-001** (wave 0, independent)
- **MSG-002** (wave 0, independent)
- **MSG-003** (wave 0, independent)
- **MSG-004** (wave 0, independent)
- **MSG-005** (wave 0, independent)
- **MSG-006** (wave 0, independent)
- **MSG-007** (wave 1, sequential) ← MSG-006
- **MSG-008** (wave 0, independent)
- **MSG-009** (wave 0, independent)
- **MSG-010** (wave 0, independent)
- **MSG-011** (wave 2, sequential) ← MSG-006, MSG-007
- **MSG-012** (wave 0, independent)

```
MSG-001
MSG-002
MSG-003
MSG-004
MSG-005
MSG-006
  └── MSG-007
    └── MSG-011
MSG-008
MSG-009
MSG-010
MSG-012
```

### NOTIFY (1 ticket)

- **NOTIFY-001** — independent
  - Cross-area deps: PLATFORM-010

### PLATFORM (19 tickets)

- **PLATFORM-001** (wave 0, independent)
- **PLATFORM-002** (wave 0, independent)
- **PLATFORM-003** (wave 0, independent)
- **PLATFORM-004** (wave 0, independent)
- **PLATFORM-005** (wave 0, independent)
- **PLATFORM-006** (wave 0, independent)
- **PLATFORM-007** (wave 1, independent) ← PLATFORM-006
- **PLATFORM-008** (wave 0, independent)
- **PLATFORM-009** (wave 0, independent)
- **PLATFORM-010** (wave 0, feature-flag-gated) ← [NOTIFY-001]
- **PLATFORM-011** (wave 2, independent) ← [SOC-003]
- **PLATFORM-012** (wave 3, sequential) ← [SOC-004]
- **PLATFORM-013** (wave 0, independent)
- **PLATFORM-014** (wave 0, independent)
- **PLATFORM-015** (wave 0, independent)
- **PLATFORM-016** (wave 1, sequential) ← PLATFORM-010
- **PLATFORM-017** (wave 7, feature-flag-gated) ← [MON-005, SOC-001, SOC-005, SOC-006, VOD-006]
- **PLATFORM-018** (wave 1, feature-flag-gated) ← [PRIVACY-001]
- **PLATFORM-019** (wave 0, independent)

```
PLATFORM-001
PLATFORM-002
PLATFORM-003
PLATFORM-004
PLATFORM-005
PLATFORM-006
  └── PLATFORM-007
PLATFORM-008
PLATFORM-009
PLATFORM-010
  └── PLATFORM-016
PLATFORM-011
PLATFORM-012
PLATFORM-013
PLATFORM-014
PLATFORM-015
PLATFORM-017
PLATFORM-018
PLATFORM-019
```

### PRIVACY (1 ticket)

- **PRIVACY-001** — independent

### PROMO (1 ticket)

- **PROMO-001** — independent

### PWA (5 tickets)

- **PWA-001** (wave 0, independent)
- **PWA-002** (wave 1, sequential) ← PWA-001
- **PWA-003** (wave 2, sequential) ← PWA-002
- **PWA-004** (wave 3, sequential) ← PWA-002, PWA-003
- **PWA-005** (wave 4, sequential) ← PWA-003, PWA-004

```
PWA-001
  └── PWA-002
    └── PWA-003
      └── PWA-004
        └── PWA-005
```

### SCHED (1 ticket)

- **SCHED-001** — independent

### SHOP (4 tickets)

- **SHOP-001** (wave 0, independent)
- **SHOP-002** (wave 1, sequential) ← SHOP-001 ← [PROMO-001]
- **SHOP-003** (wave 1, feature-flag-gated) ← [PLATFORM-006]
- **SHOP-004** (wave 0, independent)

```
SHOP-001
  └── SHOP-002
SHOP-003
SHOP-004
```

### SOC (6 tickets)

- **SOC-001** (wave 0, independent)
- **SOC-002** (wave 1, sequential) ← SOC-001
- **SOC-003** (wave 1, sequential) ← SOC-001
- **SOC-004** (wave 2, sequential) ← SOC-001 ← [NOTIFY-001]
- **SOC-005** (wave 1, sequential) ← SOC-001 ← [SOCIAL-003]
- **SOC-006** (wave 6, independent) ← SOC-001, SOC-005 ← [MON-005, VOD-006]

```
SOC-001
  └── SOC-002
  └── SOC-003
  └── SOC-004
  └── SOC-005
    └── SOC-006
```

### SOCIAL (7 tickets)

- **SOCIAL-001** (wave 0, independent)
- **SOCIAL-002** (wave 1, unknown) ← SOCIAL-004 ← [SOC-001]
- **SOCIAL-003** (wave 0, independent)
- **SOCIAL-004** (wave 0, unknown)
- **SOCIAL-005** (wave 2, independent) ← [MON-002, MON-003]
- **SOCIAL-006** (wave 0, independent)
- **SOCIAL-007** (wave 1, sequential) ← [SOC-001]

```
SOCIAL-001
SOCIAL-003
SOCIAL-004
  └── SOCIAL-002
SOCIAL-005
SOCIAL-006
SOCIAL-007
```

### SYND (6 tickets)

- **SYND-001** (wave 0, unknown)
- **SYND-002** (wave 1, unknown) ← SYND-001
- **SYND-003** (wave 2, unknown) ← SYND-001, SYND-002
- **SYND-004** (wave 1, sequential) ← SYND-001
- **SYND-005** (wave 1, sequential) ← SYND-001
- **SYND-006** (wave 2, sequential) ← SYND-001, SYND-004

```
SYND-001
  └── SYND-002
    └── SYND-003
  └── SYND-004
    └── SYND-006
  └── SYND-005
```

### UX (5 tickets)

- **UX-001** (wave 0, independent)
- **UX-002** (wave 0, independent)
- **UX-003** (wave 0, independent)
- **UX-004** (wave 0, independent)
- **UX-005** (wave 0, independent)

### VOD (21 tickets)

- **VOD-001** (wave 0, unknown)
- **VOD-002** (wave 1, independent) ← VOD-001 ← [MEDIA-002]
- **VOD-003** (wave 2, sequential) ← VOD-001, VOD-002
- **VOD-004** (wave 3, parallel) ← VOD-003 ← [MEDIA-002]
- **VOD-005** (wave 4, sequential) ← VOD-002, VOD-003, VOD-004
- **VOD-006** (wave 5, independent) ← VOD-001, VOD-005
- **VOD-007** (wave 6, sequential) ← VOD-002, VOD-006
- **VOD-008** (wave 2, sequential) ← VOD-001, VOD-010
- **VOD-009** (wave 3, sequential) ← VOD-001, VOD-008
- **VOD-010** (wave 1, sequential) ← VOD-001
- **VOD-011** (wave 4, sequential) ← VOD-001, VOD-008, VOD-009
- **VOD-012** (wave 1, sequential) ← VOD-001
- **VOD-013** (wave 1, sequential) ← VOD-001
- **VOD-014** (wave 1, sequential) ← VOD-001
- **VOD-015** (wave 1, sequential) ← VOD-001
- **VOD-016** (wave 2, sequential) ← VOD-001, VOD-015
- **VOD-017** (wave 4, sequential) ← VOD-001, VOD-009
- **VOD-018** (wave 3, sequential) ← VOD-001, VOD-008
- **VOD-019** (wave 3, sequential) ← VOD-001, VOD-008
- **VOD-020** (wave 2, sequential) ← VOD-001, VOD-012
- **VOD-021** (wave 3, sequential) ← VOD-001, VOD-008

```
VOD-001
  └── VOD-002
    └── VOD-003
      └── VOD-004
        └── VOD-005
          └── VOD-006
            └── VOD-007
  └── VOD-008
    └── VOD-009
      └── VOD-011
      └── VOD-017
    └── VOD-018
    └── VOD-019
    └── VOD-021
  └── VOD-010
  └── VOD-012
    └── VOD-020
  └── VOD-013
  └── VOD-014
  └── VOD-015
    └── VOD-016
```

---

## 8. Independent Tickets (No Upstream Dependencies)

These 101 tickets can be merged immediately in any order (Wave 0).
They have no dependencies on other tickets in this set.

- **ADMIN**: ADMIN-001, ADMIN-002, ADMIN-003
- **ADS**: ADS-001
- **AFFILIATE**: AFFILIATE-001
- **AGENT**: AGENT-001
- **BCAST**: BCAST-001
- **BILLING**: BILLING-002, BILLING-003
- **BOT**: BOT-001
- **CALL**: CALL-001
- **CREATOR**: CREATOR-002, CREATOR-003, CREATOR-004
- **DELEGATE**: DELEGATE-001
- **ENGAGE**: ENGAGE-001, ENGAGE-002, ENGAGE-003, ENGAGE-004, ENGAGE-005
- **ENTERPRISE**: ENTERPRISE-001, ENTERPRISE-004, ENTERPRISE-005
- **FEED**: FEED-001, FEED-002, FEED-003, FEED-004, FEED-005, FEED-006, FEED-007, FEED-009
- **FILES**: FILES-001
- **FIN**: FIN-001, FIN-002, FIN-003, FIN-004, FIN-005, FIN-006, FIN-007, FIN-008, FIN-009, FIN-010, FIN-011, FIN-012, FIN-013, FIN-014, FIN-015, FIN-018
- **GEO**: GEO-001
- **GROUP**: GROUP-001
- **INFRA**: INFRA-001
- **INTEG**: INTEG-001
- **KYC**: KYC-001
- **LCOM**: LCOM-001
- **LICENSE**: LICENSE-001
- **MEDIA**: MEDIA-001, MEDIA-002
- **MOD**: MOD-002, MOD-003
- **MON**: MON-002
- **MSG**: MSG-001, MSG-002, MSG-003, MSG-004, MSG-005, MSG-006, MSG-008, MSG-009, MSG-010, MSG-012
- **PLATFORM**: PLATFORM-001, PLATFORM-002, PLATFORM-003, PLATFORM-004, PLATFORM-005, PLATFORM-006, PLATFORM-008, PLATFORM-009, PLATFORM-013, PLATFORM-014, PLATFORM-015, PLATFORM-019
- **PRIVACY**: PRIVACY-001
- **PROMO**: PROMO-001
- **PWA**: PWA-001
- **SCHED**: SCHED-001
- **SHOP**: SHOP-001, SHOP-004
- **SOC**: SOC-001
- **SOCIAL**: SOCIAL-001, SOCIAL-003, SOCIAL-004, SOCIAL-006
- **SYND**: SYND-001
- **UX**: UX-001, UX-002, UX-003, UX-004, UX-005
- **VOD**: VOD-001

---

## 9. Full Topological Order

Complete merge order (280 tickets). Tickets at the same wave can be merged in parallel.

| # | Ticket | Wave | Strategy | Depends On | File |
|---|--------|------|----------|------------|------|
| 1 | **ADMIN-001** | 0 | unknown | — | `ADMIN-001-subscription-tier-manager-ui.md` |
| 2 | **ADMIN-002** | 0 | unknown | — | `ADMIN-002-admin-email-sms-dashboards.md` |
| 3 | **ADMIN-003** | 0 | unknown | — | `ADMIN-003-rate-limit-admin-ui.md` |
| 4 | **ADS-001** | 0 | independent | — | `ADS-001-advertiser-accounts-campaign-manager.md` |
| 5 | **AFFILIATE-001** | 0 | independent | — | `AFFILIATE-001-referral-system.md` |
| 6 | **AGENT-001** | 0 | independent | — | `AGENT-001-llm-provider-key-management.md` |
| 7 | **BCAST-001** | 0 | independent | — | `BCAST-001-broadcaster-dashboard.md` |
| 8 | **BILLING-002** | 0 | independent | — | `BILLING-002-payout-dashboard.md` |
| 9 | **BILLING-003** | 0 | independent | — | `BILLING-003-subscription-tier-editor.md` |
| 10 | **BOT-001** | 0 | independent | — | `BOT-001-bot-framework-lifecycle.md` |
| 11 | **CALL-001** | 0 | independent | — | `CALL-001-signaling-endpoint.md` |
| 12 | **CREATOR-002** | 0 | independent | — | `CREATOR-002-fan-clubs.md` |
| 13 | **CREATOR-003** | 0 | independent | — | `CREATOR-003-mobile-dashboard.md` |
| 14 | **CREATOR-004** | 0 | independent | — | `CREATOR-004-affiliate-links.md` |
| 15 | **DELEGATE-001** | 0 | independent | — | `DELEGATE-001-delegate-management-permissions.md` |
| 16 | **ENGAGE-001** | 0 | independent | — | `ENGAGE-001-achievements-gamification.md` |
| 17 | **ENGAGE-002** | 0 | independent | — | `ENGAGE-002-polls-surveys.md` |
| 18 | **ENGAGE-003** | 0 | independent | — | `ENGAGE-003-live-qa-mode.md` |
| 19 | **ENGAGE-004** | 0 | independent | — | `ENGAGE-004-watch-parties.md` |
| 20 | **ENGAGE-005** | 0 | independent | — | `ENGAGE-005-clip-sharing.md` |
| 21 | **ENTERPRISE-001** | 0 | independent | — | `ENTERPRISE-001-multi-tenancy.md` |
| 22 | **ENTERPRISE-004** | 0 | independent | — | `ENTERPRISE-004-audit-log-export.md` |
| 23 | **ENTERPRISE-005** | 0 | independent | — | `ENTERPRISE-005-webhooks-v2.md` |
| 24 | **FEED-001** | 0 | independent | — | `FEED-001-video-newsfeed-posts.md` |
| 25 | **FEED-002** | 0 | independent | — | `FEED-002-stories-ephemeral-content.md` |
| 26 | **FEED-003** | 0 | independent | — | `FEED-003-find-a-datetime-post.md` |
| 27 | **FEED-004** | 0 | independent | — | `FEED-004-emoji-gif-sticker-comments.md` |
| 28 | **FEED-005** | 0 | independent | — | `FEED-005-countdown-posts.md` |
| 29 | **FEED-006** | 0 | independent | — | `FEED-006-hide-post.md` |
| 30 | **FEED-007** | 0 | independent | — | `FEED-007-mark-post-interesting.md` |
| 31 | **FEED-009** | 0 | independent | — | `FEED-009-post-bookmarks-collections.md` |
| 32 | **FILES-001** | 0 | independent | — | `FILES-001-encrypted-one-time-share-links.md` |
| 33 | **FIN-001** | 0 | independent | — | `FIN-001-invoice-receipt-pdf.md` |
| 34 | **FIN-002** | 0 | independent | — | `FIN-002-promo-codes-checkout.md` |
| 35 | **FIN-003** | 0 | independent | — | `FIN-003-cart-abandonment-reminders.md` |
| 36 | **FIN-004** | 0 | independent | — | `FIN-004-consumer-tax-documents.md` |
| 37 | **FIN-005** | 0 | feature-flag-gated | — | `FIN-005-multi-currency-display.md` |
| 38 | **FIN-006** | 0 | independent | — | `FIN-006-per-content-revenue-breakdown.md` |
| 39 | **FIN-007** | 0 | independent | — | `FIN-007-platform-commission-visibility.md` |
| 40 | **FIN-008** | 0 | independent | — | `FIN-008-tax-form-generation.md` |
| 41 | **FIN-009** | 0 | independent | — | `FIN-009-payout-dashboard-frontend.md` |
| 42 | **FIN-010** | 0 | independent | — | `FIN-010-affiliate-earnings-dashboard.md` |
| 43 | **FIN-011** | 0 | independent | — | `FIN-011-collaboration-revenue-splitting.md` |
| 44 | **FIN-012** | 0 | independent | — | `FIN-012-engagement-rate-calculation.md` |
| 45 | **FIN-013** | 0 | independent | — | `FIN-013-platform-financial-dashboard.md` |
| 46 | **FIN-014** | 0 | independent | — | `FIN-014-payment-provider-health.md` |
| 47 | **FIN-015** | 0 | feature-flag-gated | — | `FIN-015-fraud-detection-dashboard.md` |
| 48 | **FIN-018** | 0 | feature-flag-gated | — | `FIN-018-billing-configuration-ui.md` |
| 49 | **GEO-001** | 0 | feature-flag-gated | — | `GEO-001-geo-blocking.md` |
| 50 | **GROUP-001** | 0 | independent | — | `GROUP-001-user-group-creation-membership.md` |
| 51 | **INFRA-001** | 0 | independent | — | `INFRA-001-host-inventory-management.md` |
| 52 | **INTEG-001** | 0 | independent | — | `INTEG-001-google-drive-picker.md` |
| 53 | **KYC-001** | 0 | independent | — | `KYC-001-admin-review-dashboard.md` |
| 54 | **LCOM-001** | 0 | independent | — | `LCOM-001-broadcast-product-shelf.md` |
| 55 | **LICENSE-001** | 0 | independent | — | `LICENSE-001-agreement-upload-management.md` |
| 56 | **MEDIA-001** | 0 | independent | — | `MEDIA-001-shared-player.md` |
| 57 | **MEDIA-002** | 0 | independent | — | `MEDIA-002-ffmpeg-binary.md` |
| 58 | **MOD-002** | 0 | independent | — | `MOD-002-dmca-takedown.md` |
| 59 | **MOD-003** | 0 | independent | — | `MOD-003-user-appeals.md` |
| 60 | **MON-002** | 0 | independent | — | `MON-002-tip-ledger-integration.md` |
| 61 | **MSG-001** | 0 | independent | — | `MSG-001-message-edit-delete.md` |
| 62 | **MSG-002** | 0 | independent | — | `MSG-002-voice-messages.md` |
| 63 | **MSG-003** | 0 | independent | — | `MSG-003-typing-realtime.md` |
| 64 | **MSG-004** | 0 | independent | — | `MSG-004-presence-realtime.md` |
| 65 | **MSG-005** | 0 | independent | — | `MSG-005-read-receipts-realtime.md` |
| 66 | **MSG-006** | 0 | independent | — | `MSG-006-emoji-messages.md` |
| 67 | **MSG-008** | 0 | independent | — | `MSG-008-gif-sticker-messages.md` |
| 68 | **MSG-009** | 0 | independent | — | `MSG-009-find-a-datetime-message.md` |
| 69 | **MSG-010** | 0 | independent | — | `MSG-010-countdown-messages.md` |
| 70 | **MSG-012** | 0 | independent | — | `MSG-012-message-formatting-rich-text.md` |
| 71 | **PLATFORM-001** | 0 | independent | — | `PLATFORM-001-rate-limiting.md` |
| 72 | **PLATFORM-002** | 0 | independent | — | `PLATFORM-002-webhooks.md` |
| 73 | **PLATFORM-003** | 0 | independent | — | `PLATFORM-003-i18n-multi-language.md` |
| 74 | **PLATFORM-004** | 0 | independent | — | `PLATFORM-004-image-optimization.md` |
| 75 | **PLATFORM-005** | 0 | independent | — | `PLATFORM-005-seo-opengraph.md` |
| 76 | **PLATFORM-006** | 0 | independent | — | `PLATFORM-006-email-production.md` |
| 77 | **PLATFORM-008** | 0 | independent | — | `PLATFORM-008-job-dashboard.md` |
| 78 | **PLATFORM-009** | 0 | independent | — | `PLATFORM-009-csv-export.md` |
| 79 | **PLATFORM-010** | 0 | feature-flag-gated | NOTIFY-001 | `PLATFORM-010-web-push-service-worker.md` |
| 80 | **PLATFORM-013** | 0 | independent | — | `PLATFORM-013-theme-customization.md` |
| 81 | **PLATFORM-014** | 0 | independent | — | `PLATFORM-014-keyboard-shortcuts.md` |
| 82 | **PLATFORM-015** | 0 | independent | — | `PLATFORM-015-drag-drop-everywhere.md` |
| 83 | **PLATFORM-019** | 0 | independent | — | `PLATFORM-019-analytics-engine.md` |
| 84 | **PRIVACY-001** | 0 | independent | — | `PRIVACY-001-gdpr-data-export.md` |
| 85 | **PROMO-001** | 0 | independent | — | `PROMO-001-promo-codes-coupons.md` |
| 86 | **PWA-001** | 0 | independent | — | `PWA-001-manifest-installable.md` |
| 87 | **SCHED-001** | 0 | independent | — | `SCHED-001-content-scheduling.md` |
| 88 | **SHOP-001** | 0 | independent | — | `SHOP-001-inventory-management.md` |
| 89 | **SHOP-004** | 0 | independent | — | `SHOP-004-carrier-tracking.md` |
| 90 | **SOC-001** | 0 | independent | — | `SOC-001-follow-system.md` |
| 91 | **SOCIAL-001** | 0 | independent | — | `SOCIAL-001-post-bookmarks.md` |
| 92 | **SOCIAL-003** | 0 | independent | — | `SOCIAL-003-global-search.md` |
| 93 | **SOCIAL-004** | 0 | unknown | — | `SOCIAL-004-user-blocking.md` |
| 94 | **SOCIAL-006** | 0 | independent | — | `SOCIAL-006-hashtags-topics.md` |
| 95 | **SYND-001** | 0 | unknown | — | `SYND-001-syndicate-creation-membership.md` |
| 96 | **UX-001** | 0 | independent | — | `UX-001-dark-mode-sync.md` |
| 97 | **UX-002** | 0 | independent | — | `UX-002-keyboard-shortcuts.md` |
| 98 | **UX-003** | 0 | independent | — | `UX-003-drag-drop-reorder.md` |
| 99 | **UX-004** | 0 | independent | — | `UX-004-bulk-operations.md` |
| 100 | **UX-005** | 0 | independent | — | `UX-005-questionnaire-analytics-ui.md` |
| 101 | **VOD-001** | 0 | unknown | — | `VOD-001-video-metadata-model.md` |
| 102 | **ADS-002** | 1 | sequential | ADS-001 | `ADS-002-ad-creative-management.md` |
| 103 | **ADS-003** | 1 | sequential | ADS-001 | `ADS-003-ad-targeting-engine.md` |
| 104 | **BCAST-002** | 1 | parallel | BCAST-001 | `BCAST-002-viewer-player.md` |
| 105 | **BCAST-003** | 1 | independent | BCAST-001 | `BCAST-003-aws-medialive-execution.md` |
| 106 | **BCAST-006** | 1 | independent | BCAST-001 | `BCAST-006-recording-archive.md` |
| 107 | **BCAST-007** | 1 | independent | BCAST-001 | `BCAST-007-sidebar-nav.md` |
| 108 | **BCAST-009** | 1 | independent | BCAST-001 | `BCAST-009-broadcast-scheduling.md` |
| 109 | **BOT-002** | 1 | sequential | BOT-001 | `BOT-002-template-scheduled-messages.md` |
| 110 | **BOT-004** | 1 | sequential | BOT-001 | `BOT-004-ai-chat-bot-llm.md` |
| 111 | **CALL-002** | 1 | sequential | CALL-001 | `CALL-002-rtc-peer-connection.md` |
| 112 | **CALL-007** | 1 | independent | CALL-001 | `CALL-007-ringing-timeout.md` |
| 113 | **DELEGATE-002** | 1 | sequential | DELEGATE-001 | `DELEGATE-002-chat-delegation.md` |
| 114 | **DELEGATE-003** | 1 | sequential | DELEGATE-001 | `DELEGATE-003-newsfeed-delegation.md` |
| 115 | **DELEGATE-004** | 1 | sequential | DELEGATE-001 | `DELEGATE-004-broadcast-chat-delegation.md` |
| 116 | **ENTERPRISE-002** | 1 | sequential | ENTERPRISE-001 | `ENTERPRISE-002-sso-saml.md` |
| 117 | **ENTERPRISE-003** | 1 | sequential | ENTERPRISE-001 | `ENTERPRISE-003-org-workspaces.md` |
| 118 | **FEED-008** | 1 | sequential | FEED-004, FEED-005 | `FEED-008-enhanced-post-composer.md` |
| 119 | **FIN-016** | 1 | sequential | FIN-013 | `FIN-016-financial-audit-log-export.md` |
| 120 | **FIN-017** | 1 | sequential | FIN-015 | `FIN-017-bulk-payout-refund-tools.md` |
| 121 | **GROUP-002** | 1 | sequential | GROUP-001 | `GROUP-002-group-page-newsfeed.md` |
| 122 | **GROUP-004** | 1 | sequential | GROUP-001 | `GROUP-004-group-treasury-management.md` |
| 123 | **INFRA-002** | 1 | sequential | INFRA-001 | `INFRA-002-ssh-key-manager.md` |
| 124 | **INFRA-010** | 1 | sequential | INFRA-001 | `INFRA-010-ssh-session-recording-playback.md` |
| 125 | **KYC-002** | 1 | sequential | KYC-001 | `KYC-002-identity-document-verification.md` |
| 126 | **KYC-003** | 1 | sequential | KYC-001 | `KYC-003-liveness-video-verification-call.md` |
| 127 | **KYC-005** | 1 | sequential | KYC-001 | `KYC-005-proof-of-funds.md` |
| 128 | **KYC-007** | 1 | sequential | KYC-001 | `KYC-007-enhanced-document-signing.md` |
| 129 | **LCOM-002** | 1 | sequential | LCOM-001 | `LCOM-002-chat-product-links.md` |
| 130 | **LCOM-003** | 1 | sequential | LCOM-001 | `LCOM-003-broadcast-checkout.md` |
| 131 | **LICENSE-002** | 1 | independent | LICENSE-001 | `LICENSE-002-content-license-issuance.md` |
| 132 | **MOD-001** | 1 | sequential | MEDIA-001 | `MOD-001-video-review-queue.md` |
| 133 | **MON-001** | 1 | independent | MEDIA-001 | `MON-001-vod-pay-per-view.md` |
| 134 | **BILLING-001** | 1 | independent | MON-002 | `BILLING-001-refunds-disputes.md` |
| 135 | **MON-003** | 1 | sequential | MON-002 | `MON-003-creator-earnings-dashboard.md` |
| 136 | **MSG-007** | 1 | sequential | MSG-006 | `MSG-007-custom-emojis.md` |
| 137 | **PLATFORM-007** | 1 | independent | PLATFORM-006 | `PLATFORM-007-sms-production.md` |
| 138 | **SHOP-003** | 1 | feature-flag-gated | PLATFORM-006 | `SHOP-003-cart-abandonment.md` |
| 139 | **NOTIFY-001** | 1 | independent | PLATFORM-010 | `NOTIFY-001-notification-delivery.md` |
| 140 | **PLATFORM-016** | 1 | sequential | PLATFORM-010 | `PLATFORM-016-web-push-delivery.md` |
| 141 | **PLATFORM-018** | 1 | feature-flag-gated | PRIVACY-001 | `PLATFORM-018-privacy-account-deletion.md` |
| 142 | **PWA-002** | 1 | sequential | PWA-001 | `PWA-002-app-shell-precaching.md` |
| 143 | **SHOP-002** | 1 | sequential | PROMO-001, SHOP-001 | `SHOP-002-promo-checkout-integration.md` |
| 144 | **SOC-002** | 1 | sequential | SOC-001 | `SOC-002-feed-fan-out.md` |
| 145 | **SOC-003** | 1 | sequential | SOC-001 | `SOC-003-user-search-discovery.md` |
| 146 | **SOCIAL-007** | 1 | sequential | SOC-001 | `SOCIAL-007-snooze-following.md` |
| 147 | **SOC-005** | 1 | sequential | SOC-001, SOCIAL-003 | `SOC-005-public-profile-page.md` |
| 148 | **SOCIAL-002** | 1 | unknown | SOC-001, SOCIAL-004 | `SOCIAL-002-post-sharing-reposts.md` |
| 149 | **SYND-002** | 1 | unknown | SYND-001 | `SYND-002-bundled-subscriptions.md` |
| 150 | **SYND-004** | 1 | sequential | SYND-001 | `SYND-004-treasury-fund-management.md` |
| 151 | **SYND-005** | 1 | sequential | SYND-001 | `SYND-005-syndicate-page-newsfeed.md` |
| 152 | **VOD-002** | 1 | independent | MEDIA-002, VOD-001 | `VOD-002-video-upload-endpoint.md` |
| 153 | **VOD-010** | 1 | sequential | VOD-001 | `VOD-010-drm-encryption.md` |
| 154 | **VOD-012** | 1 | sequential | VOD-001 | `VOD-012-optional-mp4-download.md` |
| 155 | **VOD-013** | 1 | sequential | VOD-001 | `VOD-013-video-sharing-messages.md` |
| 156 | **VOD-014** | 1 | sequential | VOD-001 | `VOD-014-vod-file-manager-bridge.md` |
| 157 | **VOD-015** | 1 | sequential | VOD-001 | `VOD-015-video-clipping.md` |
| 158 | **ADS-004** | 2 | sequential | ADS-001, ADS-002, ADS-003 | `ADS-004-ad-serving-engine.md` |
| 159 | **BCAST-004** | 2 | parallel | BCAST-001, BCAST-002 | `BCAST-004-viewer-count-health.md` |
| 160 | **BCAST-005** | 2 | independent | BCAST-001, BCAST-002 | `BCAST-005-live-chat.md` |
| 161 | **BCAST-008** | 2 | sequential | BCAST-006 | `BCAST-008-recording-mp4-download.md` |
| 162 | **BOT-003** | 2 | sequential | BOT-001, BOT-002 | `BOT-003-content-event-promotion-bot.md` |
| 163 | **BCAST-016** | 2 | independent | BCAST-001, BCAST-003, CALL-002 | `BCAST-016-broadcast-multi-input.md` |
| 164 | **CALL-003** | 2 | sequential | CALL-002 | `CALL-003-get-user-media.md` |
| 165 | **CALL-008** | 2 | sequential | CALL-002 | `CALL-008-ice-restart.md` |
| 166 | **CALL-011** | 2 | independent | CALL-002, MON-002 | `CALL-011-pay-per-minute-calls.md` |
| 167 | **CALL-012** | 2 | independent | CALL-002 | `CALL-012-group-video-calls.md` |
| 168 | **CALL-014** | 2 | independent | CALL-001, CALL-007, MSG-002 | `CALL-014-voicemail.md` |
| 169 | **DELEGATE-005** | 2 | sequential | DELEGATE-001, DELEGATE-002, DELEGATE-003, DELEGATE-004 | `DELEGATE-005-delegation-api.md` |
| 170 | **GROUP-003** | 2 | sequential | GROUP-001, GROUP-004 | `GROUP-003-group-advertising-fundraising.md` |
| 171 | **INFRA-003** | 2 | sequential | INFRA-001, INFRA-002 | `INFRA-003-ec2-instance-launcher.md` |
| 172 | **INFRA-004** | 2 | sequential | INFRA-001, INFRA-002 | `INFRA-004-kubernetes-container-launcher.md` |
| 173 | **INFRA-006** | 2 | sequential | INFRA-001, INFRA-002 | `INFRA-006-connection-profiles-quick-connect.md` |
| 174 | **INFRA-011** | 2 | sequential | INFRA-001, INFRA-002 | `INFRA-011-multi-hop-ssh-bastion.md` |
| 175 | **KYC-004** | 2 | sequential | KYC-001, KYC-002 | `KYC-004-proof-of-residency-verification.md` |
| 176 | **KYC-006** | 2 | sequential | KYC-001, KYC-002 | `KYC-006-sanctions-pep-screening.md` |
| 177 | **KYC-010** | 2 | sequential | KYC-002 | `KYC-010-passport-national-id-scanner.md` |
| 178 | **LCOM-004** | 2 | sequential | LCOM-001, LCOM-003 | `LCOM-004-broadcast-exclusive-pricing.md` |
| 179 | **LICENSE-003** | 2 | sequential | LICENSE-002 | `LICENSE-003-license-terms-revenue-sharing.md` |
| 180 | **LICENSE-004** | 2 | sequential | LICENSE-002 | `LICENSE-004-license-request-approval-workflow.md` |
| 181 | **LICENSE-006** | 2 | sequential | LICENSE-001, LICENSE-002 | `LICENSE-006-license-compliance-verification.md` |
| 182 | **MON-005** | 2 | sequential | MON-001 | `MON-005-subscription-gated-vod.md` |
| 183 | **ANALYTICS-001** | 2 | independent | MON-003 | `ANALYTICS-001-creator-analytics-dashboard.md` |
| 184 | **MON-004** | 2 | sequential | MON-002, MON-003 | `MON-004-creator-payouts.md` |
| 185 | **SOCIAL-005** | 2 | independent | MON-002, MON-003 | `SOCIAL-005-tip-leaderboards.md` |
| 186 | **MSG-011** | 2 | sequential | MSG-006, MSG-007 | `MSG-011-emoji-reactions-enhancement.md` |
| 187 | **SOC-004** | 2 | sequential | NOTIFY-001, SOC-001 | `SOC-004-notification-expansion.md` |
| 188 | **PWA-003** | 2 | sequential | PWA-002 | `PWA-003-offline-read-cache.md` |
| 189 | **BCAST-010** | 2 | sequential | BCAST-009, SOC-002 | `BCAST-010-broadcast-newsfeed-promotion.md` |
| 190 | **PLATFORM-011** | 2 | independent | SOC-003 | `PLATFORM-011-global-search.md` |
| 191 | **SYND-003** | 2 | unknown | SYND-001, SYND-002 | `SYND-003-revenue-splitting.md` |
| 192 | **SYND-006** | 2 | sequential | SYND-001, SYND-004 | `SYND-006-syndicate-advertising.md` |
| 193 | **VOD-003** | 2 | sequential | VOD-001, VOD-002 | `VOD-003-transcode-job-queue.md` |
| 194 | **VOD-008** | 2 | sequential | VOD-001, VOD-010 | `VOD-008-video-player-page.md` |
| 195 | **VOD-020** | 2 | sequential | VOD-001, VOD-012 | `VOD-020-watermarked-downloads.md` |
| 196 | **VOD-016** | 2 | sequential | VOD-001, VOD-015 | `VOD-016-video-concatenation.md` |
| 197 | **ADS-005** | 3 | sequential | ADS-001, ADS-002, ADS-004 | `ADS-005-newsfeed-sponsored-posts.md` |
| 198 | **ADS-006** | 3 | sequential | ADS-002, ADS-004 | `ADS-006-broadcast-ad-breaks.md` |
| 199 | **ADS-007** | 3 | sequential | ADS-001, ADS-004 | `ADS-007-ad-billing-financial-engine.md` |
| 200 | **ADS-015** | 3 | sequential | ADS-002, ADS-004, AFFILIATE-001 | `ADS-015-ad-creative-affiliate-discounts.md` |
| 201 | **BCAST-011** | 3 | independent | BCAST-005, CALL-001 | `BCAST-011-broadcast-go-private.md` |
| 202 | **BCAST-012** | 3 | parallel | BCAST-005, MON-002 | `BCAST-012-broadcast-private-chat-tiers.md` |
| 203 | **BCAST-013** | 3 | parallel | BCAST-005, MON-002 | `BCAST-013-broadcast-tips-goals.md` |
| 204 | **BCAST-014** | 3 | independent | BCAST-005 | `BCAST-014-broadcast-lottery.md` |
| 205 | **CREATOR-001** | 3 | independent | BCAST-016 | `CREATOR-001-collaboration-requests.md` |
| 206 | **CALL-004** | 3 | sequential | CALL-003 | `CALL-004-media-rendering.md` |
| 207 | **CALL-006** | 3 | sequential | CALL-002, CALL-003 | `CALL-006-e2e-media-tests.md` |
| 208 | **CALL-009** | 3 | sequential | CALL-002, CALL-008 | `CALL-009-call-recording.md` |
| 209 | **AGENT-002** | 3 | sequential | AGENT-001, INFRA-003, INFRA-004 | `AGENT-002-terminal-worker-provisioning.md` |
| 210 | **INFRA-005** | 3 | sequential | INFRA-003, INFRA-004 | `INFRA-005-compute-cost-tracking.md` |
| 211 | **INFRA-007** | 3 | feature-flag-gated | INFRA-003, INFRA-004 | `INFRA-007-instance-templates-presets.md` |
| 212 | **INFRA-008** | 3 | sequential | INFRA-003, INFRA-004 | `INFRA-008-instance-monitoring-health.md` |
| 213 | **INFRA-009** | 3 | sequential | INFRA-003, INFRA-004 | `INFRA-009-security-groups-network-rules.md` |
| 214 | **KYC-018** | 3 | feature-flag-gated | KYC-004 | `KYC-018-address-verification-service.md` |
| 215 | **KYC-008** | 3 | sequential | KYC-001, KYC-002, KYC-004, KYC-005, KYC-006 | `KYC-008-risk-scoring-engine.md` |
| 216 | **LICENSE-005** | 3 | sequential | LICENSE-002, LICENSE-003 | `LICENSE-005-syndicate-open-licensing.md` |
| 217 | **ANALYTICS-002** | 3 | sequential | ANALYTICS-001 | `ANALYTICS-002-creator-analytics-depth.md` |
| 218 | **PLATFORM-012** | 3 | sequential | SOC-004 | `PLATFORM-012-activity-feed.md` |
| 219 | **PWA-004** | 3 | sequential | PWA-002, PWA-003 | `PWA-004-background-sync.md` |
| 220 | **CREATOR-005** | 3 | independent | BCAST-010 | `CREATOR-005-content-calendar.md` |
| 221 | **VOD-004** | 3 | parallel | MEDIA-002, VOD-003 | `VOD-004-ffmpeg-execution.md` |
| 222 | **VOD-009** | 3 | sequential | VOD-001, VOD-008 | `VOD-009-video-routes-nav.md` |
| 223 | **VOD-018** | 3 | sequential | VOD-001, VOD-008 | `VOD-018-ad-supported-video-tier.md` |
| 224 | **VOD-019** | 3 | sequential | VOD-001, VOD-008 | `VOD-019-view-once-rental-access.md` |
| 225 | **VOD-021** | 3 | sequential | VOD-001, VOD-008 | `VOD-021-video-subtitles.md` |
| 226 | **ADS-009** | 4 | feature-flag-gated | ADS-004, ADS-005 | `ADS-009-user-ad-preferences.md` |
| 227 | **ADS-008** | 4 | sequential | ADS-001, ADS-004, ADS-007 | `ADS-008-ad-analytics-dashboard.md` |
| 228 | **ADS-010** | 4 | sequential | ADS-003, ADS-004, ADS-007 | `ADS-010-content-provider-ad-controls.md` |
| 229 | **ADS-012** | 4 | sequential | ADS-001, ADS-005, ADS-007 | `ADS-012-self-promotion-content-boosting.md` |
| 230 | **ADS-014** | 4 | sequential | ADS-001, ADS-004, ADS-007 | `ADS-014-ad-fraud-prevention.md` |
| 231 | **ADS-016** | 4 | sequential | ADS-001, ADS-004, ADS-007 | `ADS-016-ad-scheduling-dayparting.md` |
| 232 | **BCAST-015** | 4 | sequential | BCAST-005, BCAST-012, MON-002 | `BCAST-015-broadcast-rich-chat.md` |
| 233 | **CALL-005** | 4 | sequential | CALL-003, CALL-004 | `CALL-005-media-controls.md` |
| 234 | **CALL-010** | 4 | sequential | CALL-009 | `CALL-010-recording-messenger-integration.md` |
| 235 | **AGENT-003** | 4 | sequential | AGENT-002 | `AGENT-003-worker-agent-framework-lifecycle.md` |
| 236 | **INFRA-012** | 4 | sequential | INFRA-003, INFRA-004, INFRA-005 | `INFRA-012-admin-compute-dashboard.md` |
| 237 | **KYC-009** | 4 | sequential | KYC-001, KYC-008 | `KYC-009-tiered-verification-levels.md` |
| 238 | **KYC-012** | 4 | sequential | KYC-001, KYC-006, KYC-008 | `KYC-012-compliance-reporting-export.md` |
| 239 | **KYC-019** | 4 | feature-flag-gated | KYC-001, KYC-008 | `KYC-019-case-assignment-workload-management.md` |
| 240 | **PWA-005** | 4 | sequential | PWA-003, PWA-004 | `PWA-005-optimistic-offline-ui.md` |
| 241 | **VOD-005** | 4 | sequential | VOD-002, VOD-003, VOD-004 | `VOD-005-s3-upload-outputs.md` |
| 242 | **VOD-011** | 4 | sequential | VOD-001, VOD-008, VOD-009 | `VOD-011-e2e-tests.md` |
| 243 | **VOD-017** | 4 | sequential | VOD-001, VOD-009 | `VOD-017-video-gallery-hub.md` |
| 244 | **ADS-011** | 5 | sequential | ADS-001, ADS-002, ADS-008 | `ADS-011-advertiser-api.md` |
| 245 | **ADS-013** | 5 | sequential | ADS-001, ADS-007, ADS-008 | `ADS-013-sponsored-content-creator-partnerships.md` |
| 246 | **ADS-017** | 5 | sequential | ADS-001, ADS-002, ADS-004, ADS-007, ADS-008 | `ADS-017-ad-performance-optimization.md` |
| 247 | **ADS-019** | 5 | sequential | ADS-001, ADS-010 | `ADS-019-creator-self-placed-ads.md` |
| 248 | **ADS-018** | 5 | sequential | ADS-001, ADS-002, ADS-004, ADS-007, ADS-008, ADS-014 | `ADS-018-admin-ad-platform-management.md` |
| 249 | **CALL-013** | 5 | sequential | CALL-002, CALL-005, CALL-012 | `CALL-013-video-call-screenshare.md` |
| 250 | **AGENT-004** | 5 | sequential | AGENT-001, AGENT-002, AGENT-003 | `AGENT-004-worker-fleet-management-ui.md` |
| 251 | **AGENT-005** | 5 | sequential | AGENT-002, AGENT-003 | `AGENT-005-agent-memory-context-injection.md` |
| 252 | **AGENT-006** | 5 | sequential | AGENT-002, AGENT-003 | `AGENT-006-terminal-monitoring-feedback-loop.md` |
| 253 | **KYC-011** | 5 | sequential | KYC-001, KYC-009 | `KYC-011-kyc-webhooks-notifications.md` |
| 254 | **KYC-013** | 5 | sequential | KYC-009, KYC-010 | `KYC-013-user-self-service-portal.md` |
| 255 | **KYC-015** | 5 | sequential | KYC-006, KYC-009 | `KYC-015-business-corporate-accounts.md` |
| 256 | **KYC-017** | 5 | sequential | KYC-007, KYC-009 | `KYC-017-document-signing-template-library.md` |
| 257 | **KYC-022** | 5 | feature-flag-gated | KYC-002, KYC-009 | `KYC-022-electronic-identity-verification.md` |
| 258 | **KYC-023** | 5 | feature-flag-gated | KYC-001, KYC-012 | `KYC-023-data-encryption-privacy.md` |
| 259 | **KYC-024** | 5 | independent | KYC-001, KYC-008, KYC-012 | `KYC-024-analytics-funnel-dashboard.md` |
| 260 | **VOD-006** | 5 | independent | VOD-001, VOD-005 | `VOD-006-video-listing-api.md` |
| 261 | **DISC-001** | 5 | independent | SOC-001, VOD-017 | `DISC-001-content-recommendations.md` |
| 262 | **AGENT-007** | 6 | sequential | AGENT-003, AGENT-006 | `AGENT-007-agent-pr-ticket-integration.md` |
| 263 | **AGENT-008** | 6 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006 | `AGENT-008-coder-agent.md` |
| 264 | **AGENT-010** | 6 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006 | `AGENT-010-devops-sre-agent.md` |
| 265 | **AGENT-011** | 6 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006 | `AGENT-011-solution-architect-agent.md` |
| 266 | **KYC-016** | 6 | sequential | KYC-006, KYC-008, KYC-009, KYC-011 | `KYC-016-ongoing-monitoring-periodic-review.md` |
| 267 | **KYC-021** | 6 | feature-flag-gated | KYC-011 | `KYC-021-third-party-api.md` |
| 268 | **KYC-014** | 6 | sequential | KYC-010, KYC-013 | `KYC-014-facial-comparison.md` |
| 269 | **KYC-020** | 6 | feature-flag-gated | KYC-013, KYC-017 | `KYC-020-multi-language-support.md` |
| 270 | **SOC-006** | 6 | independent | MON-005, SOC-001, SOC-005, VOD-006 | `SOC-006-creator-storefront.md` |
| 271 | **VOD-007** | 6 | sequential | VOD-002, VOD-006 | `VOD-007-upload-ui-page.md` |
| 272 | **AGENT-013** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007 | `AGENT-013-product-manager-agent.md` |
| 273 | **AGENT-014** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007 | `AGENT-014-documentation-agent.md` |
| 274 | **AGENT-015** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007 | `AGENT-015-compliance-security-agent.md` |
| 275 | **AGENT-016** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007 | `AGENT-016-stylist-ui-agent.md` |
| 276 | **AGENT-017** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007 | `AGENT-017-marketing-agent.md` |
| 277 | **AGENT-018** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007 | `AGENT-018-accountant-cost-tracking-agent.md` |
| 278 | **AGENT-009** | 7 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008 | `AGENT-009-qa-agent.md` |
| 279 | **PLATFORM-017** | 7 | feature-flag-gated | MON-005, SOC-001, SOC-005, SOC-006, VOD-006 | `PLATFORM-017-creator-storefront.md` |
| 280 | **AGENT-012** | 8 | sequential | AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008, AGENT-009, AGENT-010, AGENT-011 | `AGENT-012-project-manager-agent.md` |

---

## 10. Merge Strategy Summary

### By Strategy Type

**Independent** (117 tickets):
ADS-001, AFFILIATE-001, AGENT-001, ANALYTICS-001, BCAST-001, BCAST-003, BCAST-005, BCAST-006, BCAST-007, BCAST-009, BCAST-011, BCAST-014, BCAST-016, BILLING-001, BILLING-002, BILLING-003, BOT-001, CALL-001, CALL-007, CALL-011, CALL-012, CALL-014, CREATOR-001, CREATOR-002, CREATOR-003, CREATOR-004, CREATOR-005, DELEGATE-001, DISC-001, ENGAGE-001, ENGAGE-002, ENGAGE-003, ENGAGE-004, ENGAGE-005, ENTERPRISE-001, ENTERPRISE-004, ENTERPRISE-005, FEED-001, FEED-002, FEED-003, FEED-004, FEED-005, FEED-006, FEED-007, FEED-009, FILES-001, FIN-001, FIN-002, FIN-003, FIN-004, FIN-006, FIN-007, FIN-008, FIN-009, FIN-010, FIN-011, FIN-012, FIN-013, FIN-014, GROUP-001, INFRA-001, INTEG-001, KYC-001, KYC-024, LCOM-001, LICENSE-001, LICENSE-002, MEDIA-001, MEDIA-002, MOD-002, MOD-003, MON-001, MON-002, MSG-001, MSG-002, MSG-003, MSG-004, MSG-005, MSG-006, MSG-008, MSG-009, MSG-010, MSG-012, NOTIFY-001, PLATFORM-001, PLATFORM-002, PLATFORM-003, PLATFORM-004, PLATFORM-005, PLATFORM-006, PLATFORM-007, PLATFORM-008, PLATFORM-009, PLATFORM-011, PLATFORM-013, PLATFORM-014, PLATFORM-015, PLATFORM-019, PRIVACY-001, PROMO-001, PWA-001, SCHED-001, SHOP-001, SHOP-004, SOC-001, SOC-006, SOCIAL-001, SOCIAL-003, SOCIAL-005, SOCIAL-006, UX-001, UX-002, UX-003, UX-004, UX-005, VOD-002, VOD-006

**Sequential** (133 tickets):
ADS-002, ADS-003, ADS-004, ADS-005, ADS-006, ADS-007, ADS-008, ADS-010, ADS-011, ADS-012, ADS-013, ADS-014, ADS-015, ADS-016, ADS-017, ADS-018, ADS-019, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007, AGENT-008, AGENT-009, AGENT-010, AGENT-011, AGENT-012, AGENT-013, AGENT-014, AGENT-015, AGENT-016, AGENT-017, AGENT-018, ANALYTICS-002, BCAST-008, BCAST-010, BCAST-015, BOT-002, BOT-003, BOT-004, CALL-002, CALL-003, CALL-004, CALL-005, CALL-006, CALL-008, CALL-009, CALL-010, CALL-013, DELEGATE-002, DELEGATE-003, DELEGATE-004, DELEGATE-005, ENTERPRISE-002, ENTERPRISE-003, FEED-008, FIN-016, FIN-017, GROUP-002, GROUP-003, GROUP-004, INFRA-002, INFRA-003, INFRA-004, INFRA-005, INFRA-006, INFRA-008, INFRA-009, INFRA-010, INFRA-011, INFRA-012, KYC-002, KYC-003, KYC-004, KYC-005, KYC-006, KYC-007, KYC-008, KYC-009, KYC-010, KYC-011, KYC-012, KYC-013, KYC-014, KYC-015, KYC-016, KYC-017, LCOM-002, LCOM-003, LCOM-004, LICENSE-003, LICENSE-004, LICENSE-005, LICENSE-006, MOD-001, MON-003, MON-004, MON-005, MSG-007, MSG-011, PLATFORM-012, PLATFORM-016, PWA-002, PWA-003, PWA-004, PWA-005, SHOP-002, SOC-002, SOC-003, SOC-004, SOC-005, SOCIAL-007, SYND-004, SYND-005, SYND-006, VOD-003, VOD-005, VOD-007, VOD-008, VOD-009, VOD-010, VOD-011, VOD-012, VOD-013, VOD-014, VOD-015, VOD-016, VOD-017, VOD-018, VOD-019, VOD-020, VOD-021

**Feature-Flag-Gated** (16 tickets):
ADS-009, FIN-005, FIN-015, FIN-018, GEO-001, INFRA-007, KYC-018, KYC-019, KYC-020, KYC-021, KYC-022, KYC-023, PLATFORM-010, PLATFORM-017, PLATFORM-018, SHOP-003

**Parallel** (5 tickets):
BCAST-002, BCAST-004, BCAST-012, BCAST-013, VOD-004

**Unknown** (9 tickets):
ADMIN-001, ADMIN-002, ADMIN-003, SOCIAL-002, SOCIAL-004, SYND-001, SYND-002, SYND-003, VOD-001

### Recommended Merge Process

1. **Wave 0 first**: Merge all 101 root tickets. These have no dependencies and can go in any order.
2. **Wave by wave**: After wave 0, proceed wave-by-wave. Within each wave, all tickets are independent of each other.
3. **Feature-flag-gated tickets**: These 16 tickets can technically merge at any time behind a flag, but should still respect wave order for clean integration.
4. **Cross-area coordination**: The 41 cross-area dependencies require teams to coordinate merge timing. Use the cross-area table (Section 5) as a checklist.
5. **Critical path tickets**: Foundation tickets (Section 4) should be reviewed and merged first within their wave, as delays cascade.
6. **Cycle resolution**: Merge NOTIFY-001 before PLATFORM-010 (with stub), then update after PLATFORM-010 merges.

### Risk Assessment

| Risk | Tickets | Mitigation |
|------|---------|------------|
| High fan-out (>10 dependents) | VOD-001, AGENT-002, AGENT-003, ADS-001, AGENT-001, KYC-001 | Thorough review, feature flags, integration tests |
| Deep chains (>5 levels) | INFRA→AGENT chain, VOD→PLATFORM chain | Incremental merges, CI gates between waves |
| Cross-area deps | 41 edges across 16 areas | Shared PR reviews, integration test suite |
| Dependency cycle | NOTIFY-001 ↔ PLATFORM-010 | Stub + feature flag, merge in documented order |
