# Open Bank Project → testlogon — Gap Analysis (Banking / Open-Banking API)

Generated 2026-06-12 via a 4-area multi-agent gap analysis (grounded in the live
codebase + all ticket files + ~423 existing specs). Sources:
[OBP-API repo](https://github.com/OpenBankProject/OBP-API),
[openbankproject.com](https://www.openbankproject.com/),
[platform](https://www.openbankproject.com/platform/).

## Headline

Open Bank Project (OBP) is a **bank-grade REST API platform** — banks, accounts,
balances, transactions, **transaction requests (payment initiation) with SCA**,
counterparties, **PSD2 consents (AIS/PIS)**, **account "Views"** (field-level data-sharing
delegation), fine-grained entitlements/roles, OAuth2/OIDC/DirectLogin consumers,
metrics, rate-limiting, webhooks, **dynamic entities/endpoints**, and open-data
(branches/ATMs/products/cards) across Berlin Group / UK-OB / STET standards.

**testlogon already owns the API-platform plumbing** an OBP-style API needs:
- **HAVE:** per-call API metering with per-consumer/route/product aggregates + query
  endpoints (`api_usage_metering.py`, `api_usage.py`); DDB-backed per-key rate limiting
  (`rate_limit.py`, `api_keys.py`); HMAC-signed event webhooks with a 40+ event taxonomy
  + retries (`webhook_service.py`); auto OpenAPI/Swagger; the full **SCA stack**
  (TOTP/SMS/EMAIL/WebAuthn verify + recovery, `ui_mfa.py`/`webauthn.py`) covering
  SCA-on-login & challenge/answer; rich **KYC** (documents, checks, media, sanctions,
  risk scoring, partner API).
- **PLANNED:** fine-grained per-module ACL roles + record-level security groups +
  field-level ACL (STU-002/003/004); AP supplier payment (PUR-009); double-entry GL over
  the ledger (OFB-013..018).

**The net-new is the banking *domain* model + a few platform gaps — fit varies sharply:**
testlogon moves money through a **single-entry billing ledger + per-user wallet**
(`billing_shared.py`), NOT a bank-account model. So banks/accounts/IBANs, transaction
requests, counterparties, PSD2 consents, "Views", and an OAuth2/OIDC *authorization
server* are all MISSING — but only some of these make sense for a creator-economy SaaS.

---

## Gap matrix (condensed)

### A. Banks, Accounts, Balances, Views, Transaction metadata
| Capability | Status | Evidence / note |
|---|---|---|
| Bank entity (multi-bank) | **MISSING** | no bank model; low fit |
| Bank Account entity (account_id/IBAN/routing/multi-owner/attributes/product) | **MISSING** | money is a per-user `WALLET` row (`billing_shared.py:173`), not an account |
| Balances (current/available) + list accessible accounts | **PARTIAL** | per-user balance/wallet endpoints (`billing.py:840,2483`); no per-account model |
| **Views** (named field-level access delegation: owner/accountant/auditor/public; `can_see_*` per-field grants) | **MISSING** | OBP's signature; closest is module-coarse `delegates.py` — net-new |
| Account-holder / co-access management | **PARTIAL** | org membership + delegates exist; no account object to attach to |
| Transaction metadata (tags/comments/images/narrative/geotag, blurring) | **MISSING** | ledger rows carry no user-enrichment layer |

### B. Transactions, Transaction Requests, Counterparties, Standing Orders, FX
| Capability | Status | Evidence / note |
|---|---|---|
| Transaction entity + per-account paginated list (new_balance) | **PARTIAL** | single-entry ledger (`new_ledger_entry`); no per-account view / date-range pagination / running balance |
| **Transaction Requests** (unified typed payment-initiation + INITIATED→PENDING→COMPLETED machine + get-status) | **MISSING (PARTIAL primitives)** | money moves via per-flow endpoints (deposit/tip/payout/refund); no unified request object |
| **SCA / OTP challenge gating payment execution** | **MISSING** | MFA exists for auth, not wired to a pending payment |
| **Counterparties / beneficiaries** (third-party payees, IBAN/sort-code/routing, is_beneficiary) | **MISSING** | only the user's own masked US payout destinations (`creator_payouts.py`) |
| Standing orders / scheduled recurring payments | **PARTIAL** | platform-driven recurring billing exists; no user standing-order entity |
| Direct debits (pull mandate) | **MISSING** | all flows are push |
| FX rates (get/convert pair) | **MISSING** | ledger is single-currency `usd` (FXA specs are Fixed Assets, unrelated) |
| AP supplier payment (outbound to external party) | **PLANNED** | PUR-009 |

### C. Customers/KYC, Consents & SCA, Entitlements/Roles, Consumers/OAuth
| Capability | Status | Evidence / note |
|---|---|---|
| KYC documents / checks / media / statuses | **HAVE** | `kyc_documents.py`, `kyc_document_verification.py`, sanctions, risk scoring |
| SCA challenge types (SMS/EMAIL/TOTP/WebAuthn) + answer + SCA-on-login | **HAVE** | `ui_mfa.py`, `webauthn.py` |
| Customer entity (customer_number/branch/attributes) + threaded customer messages | **PARTIAL** | KYC case has identity but no standalone customer entity / bidirectional thread |
| **PSD2 Consents (AIS/PIS)** + consent lifecycle + consent-SCA + revoke | **MISSING** | no account-info/payment-initiation consent model |
| **SCA-on-payments** (step-up before a charge settles) | **MISSING** | charge paths gate on fraud/provider only |
| Fine-grained roles / grant-revoke / list / system+bank scope | **PLANNED** | STU-002/003/004 (coarse USER/ADMIN/ROOT today) |
| **Entitlement REQUESTS** (user requests role → admin approves) | **MISSING** | no self-service request/approval queue |
| Consumer-app registration (client_id/secret, redirect URIs, scopes, enable, rotate) | **PARTIAL** | API-key registry exists; no OAuth consumer-app / secret / redirect / rotation |
| **OAuth2 / OIDC authorization server** (authorize/token, OIDC discovery) | **MISSING** | testlogon is only an OAuth *client* (Cognito/cookie/SAML inbound) |

### D. Metrics, Rate-limiting, Webhooks, API Explorer, Dynamic, Open-data
| Capability | Status | Evidence / note |
|---|---|---|
| API metrics (record + per-consumer/route/product aggregates + query) | **HAVE** | `api_usage_metering.py`, `api_usage.py` |
| Top-N consumers/endpoints leaderboard | **PARTIAL** | aggregates exist; no ranked leaderboard endpoint |
| Per-key rate limiting | **HAVE/PARTIAL** | `rate_limit.py` buckets; not a uniform all-route per-consumer throttle |
| Rate-limit on consent | **MISSING** | no consent object |
| HMAC event webhooks (register/sign/deliver/retry/rotate) | **HAVE** | `webhook_service.py` |
| account.* / transaction.created / balance.threshold webhook events | **PARTIAL** | event taxonomy is billing/messaging, not account/ledger events |
| OpenAPI/Swagger | **HAVE** | `GET /openapi.json`, `/docs` |
| Glossary endpoint | **MISSING** | net-new |
| Multi-standard API (Berlin Group/UK-OB/STET side-by-side) | **MISSING → DE-SCOPE** | bank-regulatory; low fit |
| **Dynamic Entities / Dynamic Endpoints** (runtime schema → CRUD; register endpoint) | **MISSING** | no runtime API generator |
| Open-data Branches / ATMs | **MISSING** | physical-bank open-data; low fit |
| Financial Products / Product Collections | **PARTIAL** | catalog is a shop-SKU analogue |
| Cards as a managed resource (list/create/status/attributes) | **PARTIAL** | payment-methods store covers card list/add/default |
| Connectors (pluggable backend) | **PARTIAL** | provider-abstraction exists |
| Sandbox JSON data import | **PARTIAL** | seed scripts exist; no admin import endpoint |

---

## Recommended new tickets — fit-tiered (prefix **`OBP`**)

**Tier 1 — High-fit platform enhancements (~14 tickets).** Genuinely improve testlogon's
existing API/billing/security platform regardless of "banking":
- **OAuth2 / OIDC authorization server** + **consumer-app registry** (client_id/secret,
  redirect URIs, scopes, enable/disable, key rotation) — lets third parties build on the
  API; big value. (~4 tickets)
- **Transaction Requests + step-up SCA on payments**: a unified typed money-movement
  request object (INITIATED→PENDING→COMPLETED) with an OTP/SCA challenge gating execution
  on high-value/sensitive transfers (reuse the MFA stack + ledger primitives). (~3)
- **Account "Views" / field-level delegation** generalized from `delegates.py` — grant a
  scoped, field-level read of financial/account data to another user (tax/auditor/public).
  (~2)
- **Entitlement-request workflow** (self-service role request → admin approval queue) over
  STU ACL. (~1)
- **Per-consumer rate-limit middleware** (configurable windows on all metered routes) +
  **top-N metrics leaderboard** + **glossary endpoint** + **sandbox JSON import**. (~4)

**Tier 2 — Banking data model (~14 tickets).** The OBP bank/account/transaction surface
mapped onto the wallet/ledger:
- **Bank + Account entities** (account_id, label, type, multi-owner, typed attributes) over
  wallet/ledger; per-account **transaction list** (date-range/cursor pagination, running
  `new_balance`, typed `amount{currency,value}`); **transaction metadata enrichment**
  (tags/comments/narrative/geotag/images).
- **Counterparties/beneficiaries** (third-party payees w/ routing) consumed by
  COUNTERPARTY transaction requests; **standing orders**; **direct-debit mandates**;
  **FX rates** (get/convert) for cross-currency.
- **Customer entity** (customer_number/branch/attributes) + user↔customer link + threaded
  customer messages; **Cards** as a managed resource; **financial Products/Collections**.
- **account.*/transaction.* webhook events**.

**Tier 3 — Open-banking compliance + extensibility + open-data (~10 tickets).** Lowest fit:
- **PSD2 Consents (AIS/PIS)** — consent grant/lifecycle/SCA/revoke + consent-scoped rate
  limit.
- **Dynamic Entities / Dynamic Endpoints** (runtime schema → generated CRUD; register
  custom endpoint).
- **Open-data Branches / ATMs**.
- **DE-SCOPE recommended:** multi-standard adapters (Berlin Group / UK-OB / STET) — large,
  bank-regulatory, poor fit for a creator-economy SaaS.

**Already HAVE/PLANNED → NO new ticket:** API metrics, per-key rate limiting, HMAC
webhooks, OpenAPI, the SCA challenge/answer stack, KYC docs/checks/media/status, SCA-on-
login, fine-grained ACL (STU-002/003/004), AP supplier payment (PUR-009), GL (OFB-013..018).

## Scope tiers (for the build decision)
- **Tier 1 — High-fit platform enhancements:** ~14 tickets (OAuth2/OIDC, txn-requests+SCA, views, entitlement-requests, rate-limit/metrics/glossary/import)
- **Tier 2 — Banking data model:** ~14 (banks/accounts/transactions/counterparties/standing-orders/FX/cards/products/customers)
- **Tier 3 — Open-banking compliance + extensibility:** ~10 (PSD2 consents, dynamic entities/endpoints, branches/ATMs; multi-standard de-scoped)
- **Everything (T1–T3):** ~38 (excluding the de-scoped multi-standard adapters)

All additive + flag-gated default-off, reusing existing primitives (ledger/wallet, MFA/SCA,
api-keys/scopes, metrics, rate_limit, webhooks, KYC, STU ACL) — never forking.
