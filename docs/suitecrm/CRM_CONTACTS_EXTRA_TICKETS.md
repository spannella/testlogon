# CRM Contacts Extra Tickets — Accounts, Contacts & Relationships

**Area:** Accounts, Contacts & Relationships (SuiteCRM Tier 1)

**What SuiteCRM provides that testlogon currently lacks:**  
SuiteCRM's Accounts module carries rich business metadata (industry, website, employee count, revenue) on organization records, supports an account hierarchy (parent/member-of relationships between org accounts), a reports-to manager chain between contacts, duplicate detection and merge across CRM records, and vCard (.vcf) import/export for standard address-book interoperability. The testlogon platform has a functional social-graph contacts surface (`app/routers/contacts.py`) and a planned 15-ticket OFBiz Party/CRM buildout (PTY-001..PTY-015 in `PARTY_CRM_TICKETS.md` and `docs/ofbiz/specs/`), but none of those tickets are yet implemented and none of them address these six capabilities.

**Cross-cutting constraints for all tickets in this file:**
- All changes are **additive and flag-gated default-off**; existing surfaces are byte-for-byte unchanged with flags off.
- Single-table DynamoDB on the `party` table (defined by PTY-002); numeric GSI sort keys must use `attr_types={"created_at": "N"}` per CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha.
- Reuse existing primitives: `app/services/alerts.audit_event`, `app/core/normalize.py`, `app/core/cursor.py`, `app/core/time.now_ts()`, `app/services/sessions.require_ui_session`.
- Never fork — extend the party service (`app/services/party.py`) and the party router (`app/routers/party.py`) defined by PTY-004..PTY-011.
- Dev/prod parity (SECOPS-007): no `dev_mode` branches; same code path in both environments.
- Hermetic offline tests: moto-bound frozen `T.party` via `object.__setattr__`, frozen `S` flags via `object.__setattr__`, no real AWS/network.

---

### CCT-001: Account industry and business metadata fields
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the `CrmOrgAccountOut` response model (defined in PTY-003 at `docs/ofbiz/specs/PTY-003.md:537–545` as a `BaseModel` with `party_id`, `name`, `status`, `roles`, `member_count`, `created_at`, `updated_at`) with five additive SuiteCRM Account fields:

```
industry:        Optional[str] = None   # picklist: Technology, Finance, Healthcare, …
website:         Optional[str] = None   # max 2048 chars, validated as URL prefix
phone:           Optional[str] = None   # normalized via app/core/normalize.normalize_phone
employee_count:  Optional[int] = None   # ge=0
annual_revenue_cents: Optional[int] = None  # ge=0, stored as integer cents
```

Add a matching `CrmOrgAccountUpdateIn` request model (parallel to the update-party pattern in PTY-004) for the PATCH endpoint. Persist the five new fields on the `PARTY_GROUP` META DDB row in `app/services/party.py::create_org_account` and in a new `update_org_account(org_party_id, actor_party_id, **fields)` helper (requires the actor to hold `ORG_ADMIN` on the org, checked via the existing `_assert_org_admin` helper from PTY-008).

Wire the PATCH endpoint `PATCH /ui/party/orgs/{org_party_id}` in `app/routers/party.py` (added by PTY-012) using `CrmOrgAccountUpdateIn` as the request body and `CrmOrgAccountOut` as the response. Declare the `PATCH /orgs/{org_party_id}` route after the existing `GET /orgs/{org_party_id}` in declaration order so it does not disturb PTY-012's existing route set.

Validate `industry` against a fixed picklist (`INDUSTRY_CHOICES` constant in `app/services/party.py`); unknown values return `400`. Validate `website` with a loose regex (`^https?://`) if non-empty. Phone is normalized through `app/core/normalize.normalize_phone` (the same try/except → ValueError pattern used by `RegisterStartReq._normalize_phone` at `app/models.py:154-157`).

All five fields are written to and read from the META DDB row; they are stored as `None`-absent (no NULL/empty string stored for optional absent fields). The existing `get_org_account` / `list_org_accounts` projections are updated to populate them in `CrmOrgAccountOut`.

**Acceptance Criteria**
- `POST /ui/party/orgs` can accept and persist all five new fields.
- `PATCH /ui/party/orgs/{id}` updates any subset of the five fields; only ORG_ADMIN actors can call it; non-admins get 403.
- `GET /ui/party/orgs/{id}` returns populated fields in `CrmOrgAccountOut`.
- Unknown `industry` value returns 400; malformed website returns 400; phone is normalized to E.164.
- With `party_crm_org_accounts_enabled` off, the PATCH route returns 503 and no DDB write occurs.
- Hermetic pytest covers create-with-fields / PATCH subset / authz / flag-off / field validation.

**Dependencies**
- PTY-003 (models), PTY-004 (party CRUD), PTY-008 (org account service + `_assert_org_admin`), PTY-011 (router scaffolding), PTY-012 (org router endpoints).
- Flag: `PARTY_CRM_ORG_ACCOUNTS_ENABLED` (existing, from PTY-001).

---

### CCT-002: Account hierarchy (parent account / member organizations)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a `PARENT_ORG` relationship type to the `CrmRelationshipType` enum in `app/models.py` (currently `EMPLOYMENT`, `GROUP_MEMBER`, `CONTACT_REL`, `OWNER` — defined by PTY-003 at `docs/ofbiz/specs/PTY-003.md:215–222`). `PARENT_ORG` connects two `PARTY_GROUP` parties: `from_party_id` = child org, `to_party_id` = parent org.

Add two helpers to `app/services/party.py`:

- `set_parent_org(child_org_id, parent_org_id, *, actor_party_id)` — validates both parties are `PARTY_GROUP`, validates no circular chain (walk the PARENT_ORG chain up to a depth of 10; raise `400 circular_hierarchy` if `child_org_id` appears), writes a `PARENT_ORG` edge via the existing `create_relationship` (PTY-006), and replaces any prior PARENT_ORG edge for the child (only one parent allowed — conditional delete of old edge before write).
- `get_org_hierarchy(org_party_id, *, direction="children"|"ancestors"|"both")` — returns the flat list of immediate children (`GSI3` reverse lookup on `PARENT_ORG`) or the ancestor chain (walk primary edges up) up to depth 10. Returns `{"ancestors": [...], "children": [...]}` shaped as `List[CrmRelationshipOut]`.

Add two router endpoints to `app/routers/party.py` under the existing `/ui/party/orgs/{org_party_id}` group (PTY-012):

```
PUT  /ui/party/orgs/{org_party_id}/parent         — set_parent_org; actor must hold ORG_ADMIN
DELETE /ui/party/orgs/{org_party_id}/parent       — remove parent link; actor must hold ORG_ADMIN
GET  /ui/party/orgs/{org_party_id}/hierarchy      — get_org_hierarchy; any party member can call
```

Persist uses the existing `REL#{relationship_type}#{to_party_id}` SK and `MIRROR` GSI3 pattern established by PTY-006 at `docs/ofbiz/specs/PTY-006.md:152–198`. No new DDB table or GSI is required.

Also add `parent_org_party_id: Optional[str] = None` and `child_org_count: int = 0` to `CrmOrgAccountOut` (CCT-001) so the GET org-detail endpoint surfaces the immediate parent and the number of child organizations.

**Acceptance Criteria**
- Setting a parent creates a `PARENT_ORG` edge; replacing it removes the old one.
- Circular hierarchy (A→B→C→A) is rejected with 400.
- `GET /hierarchy` returns correct ancestor and child lists.
- Only one parent per org; child count is correct.
- Non-ORG_ADMIN actor on PUT/DELETE gets 403.
- With flag off, all three routes return 503.
- Hermetic pytest covers set/replace/remove/circular-reject/authz/flag-off.

**Dependencies**
- CCT-001 (extends `CrmOrgAccountOut`), PTY-003 (enum extension), PTY-006 (create_relationship reuse), PTY-008 (`_assert_org_admin`), PTY-011/PTY-012 (router scaffold).
- Flag: `PARTY_CRM_ORG_ACCOUNTS_ENABLED` (existing, from PTY-001).

---

### CCT-003: Reports-to hierarchy on Contacts (manager chain)
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Add a `REPORTS_TO` relationship type to `CrmRelationshipType` in `app/models.py` (`docs/ofbiz/specs/PTY-003.md:215–222`). `REPORTS_TO` connects two `PERSON` parties: `from_party_id` = direct report, `to_party_id` = manager.

Add two helpers to `app/services/party.py`:

- `set_manager(person_party_id, manager_party_id, *, actor_party_id)` — validates both parties are `PERSON`, validates no circular management chain (depth ≤ 10 walk; raise `400 circular_reports_to`), writes a `REPORTS_TO` edge via `create_relationship` (PTY-006), replaces any prior `REPORTS_TO` edge for the person (only one direct manager allowed).
- `get_reports_to_chain(person_party_id, *, direction="reports"|"manager_chain")` — `direction="reports"` returns direct reports of this person via `GSI3` reverse lookup; `direction="manager_chain"` walks REPORTS_TO edges upward and returns the chain.

Add two router endpoints to `app/routers/party.py` (PTY-011):

```
PUT  /ui/party/parties/{party_id}/manager         — set_manager; require_ui_session
DELETE /ui/party/parties/{party_id}/manager       — remove manager link; require_ui_session
GET  /ui/party/parties/{party_id}/reports-to      — get_reports_to_chain; require_ui_session
```

Declare these routes in the `/parties/{party_id}` sub-group that PTY-011 establishes, after any static segments (`/parties/lookup`) to preserve FastAPI's declaration-order matching (CLAUDE.md "schedules before /{export_id}" gotcha).

Uses the existing `REL#REPORTS_TO#…` SK and `MIRROR` GSI3 mirror pattern from PTY-006 (`docs/ofbiz/specs/PTY-006.md:152–198`). No new DDB table or GSI.

Add `manager_party_id: Optional[str] = None` and `direct_report_count: int = 0` to `CrmPartyOut` so the GET party-detail endpoint surfaces the manager reference.

**Acceptance Criteria**
- Setting a manager creates a `REPORTS_TO` edge; replacing it removes the old one first.
- Circular chain (A reports to B reports to A) is rejected with 400.
- `GET /reports-to?direction=reports` returns direct reports via GSI3.
- `GET /reports-to?direction=manager_chain` walks the chain to depth 10.
- Setting `REPORTS_TO` on a `PARTY_GROUP` party is rejected with 400.
- With flag off, routes return 503.
- Hermetic pytest covers set/replace/remove/circular-reject/type-guard/flag-off.

**Dependencies**
- PTY-003 (enum extension), PTY-006 (create_relationship reuse), PTY-011 (router scaffold).
- Flag: `PARTY_CRM_ENABLED` (existing, from PTY-001).

---

### CCT-004: Duplicate contact detection
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Add a duplicate detection service to `app/services/party_dedup.py` that scores candidate party pairs for likely duplication. The scoring algorithm reuses two existing patterns:

1. **Exact contact-mech match** — call `find_party_by_contact` (PTY-007) with each `EMAIL`/`PHONE` contact mech on the candidate party to find parties sharing the same normalized email or phone. An exact EMAIL match scores 0.90; an exact PHONE match scores 0.80.
2. **Fuzzy name match** — normalize display names using the same `_normalize_name` pattern from `app/services/kyc_sanctions_screening.py:205–211` (lowercase, strip diacritics, collapse non-alphanumeric to spaces) and apply `difflib.SequenceMatcher` ratio (same import pattern as `kyc_sanctions_screening.py:39, 235`). A ratio ≥ 0.85 contributes a name-similarity score of `ratio × 0.70`.

Total score = max of all signal scores (capped at 1.0). Pairs scoring ≥ `DEDUP_MATCH_THRESHOLD` (default 0.70, env `PARTY_DEDUP_MATCH_THRESHOLD`) are returned as `DuplicateCandidateOut` (`party_a_id`, `party_b_id`, `score`, `match_signals: List[str]`).

Service functions:
- `find_duplicates_for_party(party_id, *, actor_sub) -> List[DuplicateCandidateOut]` — scores the given party against all parties sharing at least one contact mech (via GSI2) or a similar name (prefix-scan `GSI_CREATED` with normalized name token prefix, max 200 candidates).
- `list_all_duplicate_candidates(actor_sub, cursor=None) -> (List[DuplicateCandidateOut], cursor)` — admin sweep that pages through `PARTY_GROUP` and `PERSON` parties and returns pairs above threshold, paginated via `app/core/cursor.encode_cursor`.

Add models to `app/models.py`:
```
class DuplicateCandidateOut(BaseModel):
    party_a_id:    str
    party_b_id:    str
    score:         float
    match_signals: List[str]
```

Add two router endpoints to `app/routers/party.py` (PTY-011):
```
GET /ui/party/parties/{party_id}/duplicates   — find_duplicates_for_party; require_ui_session
GET /ui/admin/party/duplicate-candidates      — list_all_duplicate_candidates; require_admin_session
```

Declare `/ui/admin/party/duplicate-candidates` in a separate admin sub-router block (same pattern as `POST /ui/admin/party/migrate-contacts` in PTY-012). Emit `audit_event("party.duplicate_scan", actor_sub, ...)` on every call to `list_all_duplicate_candidates` via `app.services.alerts.audit_event`.

Gate the entire feature with `S.party_crm_enabled`; return 503 when off.

**Acceptance Criteria**
- Two parties sharing the same normalized EMAIL are detected with score ≥ 0.90.
- Two parties with display names at SequenceMatcher ratio ≥ 0.85 are detected with name_similarity signal.
- A party with no contact mechs and a unique name has no duplicates returned.
- `list_all_duplicate_candidates` paginates correctly and emits an audit event.
- Admin endpoint requires `require_admin_session`; regular user endpoint requires `require_ui_session`.
- Threshold is configurable via env `PARTY_DEDUP_MATCH_THRESHOLD`.
- With flag off, both routes return 503.
- Hermetic pytest: moto-bound `T.party`, covers exact-email match / fuzzy-name match / no-match / pagination / audit-event emission.

**Dependencies**
- PTY-004, PTY-007 (`find_party_by_contact` reuse), PTY-011/PTY-012 (router scaffold).
- Flag: `PARTY_CRM_ENABLED` (existing, from PTY-001).

---

### CCT-005: Contact merge (consolidate two party records)
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Add `merge_parties(winner_party_id, loser_party_id, *, actor_sub)` to `app/services/party.py`. The merge operation:

1. **Validate**: both parties exist; they are the same `party_type`; `winner != loser`; actor is either the owner of both parties or holds `role >= ADMIN` (checked via `ctx["role"]` from `require_admin_session`).
2. **Copy roles**: for each `ROLE#*` row on `loser` that the `winner` doesn't already hold, write a new `ROLE#*` row on `winner` (reuse `add_role` from PTY-005, idempotent).
3. **Copy relationships**: for each `REL#*` row on `loser`, re-point to `winner` via `create_relationship` (PTY-006) if the same relationship doesn't already exist on `winner`. Mirror rows (`MIRROR#`) on the other parties are similarly updated.
4. **Copy contact mechs**: for each `MECH#*` row on `loser` (from PTY-007), check if `winner` already has a mech with the same normalized value; if not, copy the mech row onto `winner` (new `mech_id = uuid4().hex`). The GSI2 reverse-lookup rows are written for the copied mechs.
5. **Mark loser**: call `update_party_status(loser_party_id, CrmPartyStatus.MERGED)` (PTY-004), and write `merged_into_party_id` onto the loser META row.
6. **Audit**: emit `audit_event("party.merged", actor_sub, winner_party_id=winner_party_id, loser_party_id=loser_party_id)` via `app.services.alerts.audit_event`.

No hard-delete of the loser row — it remains as a `MERGED` status tombstone. `get_party(loser_id)` still returns the row with `status=MERGED` so any cached references resolve. `CrmPartyStatus.MERGED` is already defined in PTY-003 (`docs/ofbiz/specs/PTY-003.md:189–196`).

Add `CrmMergePartyIn(winner_party_id: str, loser_party_id: str)` to `app/models.py`.

Add a router endpoint:
```
POST /ui/party/parties/merge         — merge_parties; require_admin_session
```
Declare `/ui/party/parties/merge` as a static segment **before** `/{party_id}` in `app/routers/party.py` to prevent FastAPI capturing the literal `merge` as a path parameter (CLAUDE.md gotcha). Under `require_admin_session` (the same dep used by `POST /ui/admin/party/migrate-contacts` in PTY-012, from `app/auth/deps.py`).

**Acceptance Criteria**
- After merge, `get_party(winner_id)` carries all roles and mechs from both winner and loser.
- After merge, `get_party(loser_id).status == "MERGED"` and `loser.merged_into_party_id == winner_id`.
- Merging two parties of different types (PERSON vs PARTY_GROUP) returns 400.
- Self-merge returns 400.
- Non-admin caller gets 403.
- Duplicate roles/mechs on the winner are not duplicated (idempotent copy).
- Audit event is emitted on success.
- With flag off, route returns 503.
- Hermetic pytest: moto-bound `T.party`; covers role copy / mech copy / relationship re-point / loser tombstone / duplicate-prevention / authz / flag-off.

**Dependencies**
- CCT-004 (natural precursor — merge resolves detected duplicates), PTY-004 (update_party_status), PTY-005 (add_role), PTY-006 (create_relationship), PTY-007 (contact mech copy), PTY-011/PTY-012 (router scaffold).
- Flag: `PARTY_CRM_ENABLED` (existing, from PTY-001).

---

### CCT-006: vCard import and export
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Add vCard 3.0/4.0 import and export to the party surface so standard address-book clients can exchange contacts with the platform.

#### Export — `GET /ui/party/parties/{party_id}/vcard`

Add `export_party_as_vcard(party_id, *, actor_sub) -> bytes` to `app/services/party_vcard.py` (new file). Builds a vCard 3.0 `.vcf` file from the party's `CrmPartyOut` + contact mechs (`list_contact_mechs`, PTY-007):

- `FN`/`N` — from the `name`/`display_name` field on the META row (PERSON: split on space for `N:last;first`; PARTY_GROUP: `ORG` field).
- `EMAIL` — from every `EMAIL` contact mech; `type=WORK` if purpose includes `WORK`, `type=HOME` if `HOME`, else `type=INTERNET`.
- `TEL` — from every `PHONE` contact mech in normalized E.164 form.
- `ADR` — from every `POSTAL` contact mech, using the stored `postal_address` sub-object fields (line1, line2, city, state, postal_code, country).
- `TITLE`/`ORG` — if the party has an `EMPLOYMENT` relationship, populate `ORG` from the linked PARTY_GROUP name.
- `UID` — `party_id`.
- `REV` — `updated_at` as ISO8601 UTC string.

Returns raw UTF-8 bytes with `Content-Type: text/vcard; charset=UTF-8`, `Content-Disposition: attachment; filename="{display_name}.vcf"`. No external library; pure-Python string formatting (follows the self-contained pattern of `app/services/receipts.py` and `app/services/audit_export_pipeline.py`).

Router endpoint in `app/routers/party.py` under `require_ui_session`. Declare before `/{party_id}` group-level routes to avoid capture issues. Returns `fastapi.Response(content=vcf_bytes, media_type="text/vcard")`.

#### Import — `POST /ui/party/vcard-import`

Add `import_vcard(vcf_bytes, *, actor_sub) -> List[CrmPartyOut]` to `app/services/party_vcard.py`. Parses one or more vCard records from the uploaded `.vcf` payload (multipart or `application/octet-stream`):

- Parse with a minimal self-contained vCard line-parser (fold-aware: joins lines that start with a single space, splits on `:`/`;`, handles `QUOTED-PRINTABLE` and `BASE64` encodings as passthrough).
- For each vCard record:
  1. Determine `party_type`: `PARTY_GROUP` if `ORG` is present and `N` is absent, else `PERSON`.
  2. Create the party via `create_party` (PTY-004) with `correlation_id = sha256(FN + EMAIL[0])` for idempotent re-import.
  3. Add each `EMAIL`/`TEL`/`ADR` field as a contact mech via `add_contact_mech` (PTY-007); skip if the mech already exists on the party (dedup via `find_party_by_contact`).
  4. Emit `audit_event("party.vcard_import", actor_sub, party_id=..., source="vcf")`.
- Returns the list of created (or existing-by-idempotency) `CrmPartyOut` records.
- Cap at 500 vCard records per request (return 400 `too_many_vcards` if exceeded).

Router endpoint `POST /ui/party/vcard-import` in `app/routers/party.py` under `require_ui_session`, declared before `/{party_id}` routes. Accepts `File(...)` multipart upload.

Both import and export are gated by `S.party_crm_enabled`; return 503 when off. No S3 storage — import reads the upload in-memory; export streams bytes directly.

**Acceptance Criteria**
- `GET /{party_id}/vcard` for a PERSON party with email + phone + postal produces a valid vCard 3.0 with `FN`, `EMAIL`, `TEL`, and `ADR` lines.
- `GET /{party_id}/vcard` for a PARTY_GROUP party uses the `ORG` line.
- `POST /vcard-import` with a single-record `.vcf` creates a PERSON party and contact mechs; re-importing the same `.vcf` returns the existing party (idempotent).
- Multi-record `.vcf` (≤ 500 records) creates one party per record.
- Import exceeding 500 records returns 400.
- `TEL` values are normalized via `normalize_phone` during import (try/except → ValueError pattern per PTY-003).
- Malformed `EMAIL` lines are skipped (not fatal to the whole import).
- With flag off, both routes return 503.
- Hermetic pytest: mock `T.party` (moto-bound); covers export field mapping / import idempotency / multi-record / limit enforcement / phone normalization / flag-off.

**Dependencies**
- PTY-004 (`create_party`), PTY-007 (`add_contact_mech`, `find_party_by_contact`, `list_contact_mechs`), PTY-011 (router scaffold).
- Flag: `PARTY_CRM_ENABLED` (existing, from PTY-001).
