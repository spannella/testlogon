---
id: AND-007
title: Wrapper, .gitignore, module README
milestone: M1
epic: E01
priority: P1
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-001]
blocks: [AND-002, AND-003, AND-004, AND-005, AND-006]
---

# AND-007 — Wrapper, .gitignore, module README

## 1. Overview & Goal

This ticket makes the `android/` subproject of the `spannella/testlogon` monorepo **reproducibly buildable from a clean clone with zero out-of-band setup**. It commits three categories of repository hygiene artifacts that AND-001 (Gradle project skeleton) created on the author's machine but did not yet version:

1. The **Gradle wrapper** (`gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`, `gradle/wrapper/gradle-wrapper.properties`) pinned to **Gradle 8.9**, so that every contributor and the CI build-server use the exact same Gradle distribution without a host-installed `gradle`.
2. An Android-aware **`.gitignore`** scoped to `android/` that excludes generated build output, IDE state, local SDK pointers, and secrets, while *keeping* the wrapper jar and version catalog tracked.
3. A developer-facing **`android/README.md`** documenting prerequisites, clone-to-run steps, the test commands, the product **flavors**, and — critically — the **base-URL switch** that lets a developer point the app at the flaky plaintext dev backend (`http://18.222.237.167:8000`) or a local mock.

This is a **Chore** (P1). It owns no runtime code, no UI, and no network calls. Its single measurable outcome: a teammate who has never touched the project can run `git clone … && cd testlogon/android && ./gradlew :app:assembleDebug` and get an APK, guided only by the committed README.

## 2. Context & References

- **Repo / layout:** `spannella/testlogon`, Android app lives in the monorepo subfolder `android/` on branch `android-port`. The web reference app is under `frontend/`; the FastAPI + DynamoDB backend is the API source of truth.
- **Toolchain (must match build-server):** JDK 17, Gradle **8.9** wrapper, AGP **8.7.3**, Kotlin **2.0.21**, KSP, compileSdk/targetSdk **35**, minSdk **24**.
- **Canonical package / applicationId base:** `com.testlogon.android` (referenced verbatim in the README's flavor and `applicationId` notes).
- **Dev backend:** `http://18.222.237.167:8000` — **plaintext HTTP**, unreliable dev host. README documents that this requires a cleartext-permitted build and warns about ~20s timeouts / flakiness so newcomers do not file false bug reports.
- **Upstream dependency:** AND-001 produced `settings.gradle.kts`, root `build.gradle.kts`, `gradle.properties`, and `gradle/libs.versions.toml`. AND-007 commits the wrapper that drives those, plus the ignore/readme files around them.
- **Downstream consumers:** AND-002 (app module config / `assembleDebug`), AND-003+ (modules, CI) all assume a committed wrapper and a working clean clone; this ticket unblocks them.
- **External references:** Gradle wrapper docs (`gradle wrapper --gradle-version`); Android Studio's generated `.gitignore` template; the GitHub `Android.gitignore` collection (used as a baseline, then trimmed to this project).

## 3. Functional Requirements

**FR-1 — Wrapper committed and pinned.** The following four files MUST be tracked in git under `android/`:
```
android/gradlew
android/gradlew.bat
android/gradle/wrapper/gradle-wrapper.jar
android/gradle/wrapper/gradle-wrapper.properties
```
`gradle-wrapper.properties` MUST pin `distributionUrl` to Gradle **8.9** (`-bin` distribution) and MUST include `distributionSha256Sum` for supply-chain integrity. `gradlew` MUST be committed with the executable bit set (git mode `100755`).

**FR-2 — `.gitignore` excludes generated artifacts.** `android/.gitignore` MUST ignore: `.gradle/`, `**/build/`, `local.properties`, `.idea/` (except shared run/code-style configs if any), `*.iml`, `captures/`, `.cxx/`, `*.keystore`/`*.jks`, `*.apk`/`*.aab`, `.kotlin/`, and `secrets.properties`. It MUST **not** ignore `gradle-wrapper.jar`, `gradle/libs.versions.toml`, or `gradlew`/`gradlew.bat`.

**FR-3 — README documents clean-clone build.** `android/README.md` MUST contain copy-pasteable commands for: prerequisites, build (`:app:assembleDebug`), install/run, unit tests, and instrumented tests, all invoked through `./gradlew` (and `gradlew.bat` for Windows).

**FR-4 — README documents flavors.** README MUST list the product flavors and the resulting `applicationId` per flavor (base `com.testlogon.android`), so a reader can predict the installed package name.

**FR-5 — README documents the base-URL switch.** README MUST explain how to select the API base URL (dev flaky host vs. local mock vs. staging), where the value is defined, and how to override it locally without editing tracked files.

**FR-6 — No secrets committed.** No keystore, password, token, or `local.properties` may be introduced by this ticket; the `.gitignore` enforces this going forward.

## 4. Technical Design

This ticket produces configuration/text files only — **no Kotlin runtime code**. The "design" is the precise content of the three artifacts and the verification harness.

**4.1 Wrapper generation.** Generated reproducibly from the AND-001 skeleton:
```bash
cd android
gradle wrapper --gradle-version 8.9 --distribution-type bin
# then capture the published checksum and pin it:
./gradlew wrapper --gradle-version 8.9 \
  --gradle-distribution-sha256-sum <sha256-of-gradle-8.9-bin.zip>
```
Resulting `gradle/wrapper/gradle-wrapper.properties`:
```properties
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-8.9-bin.zip
distributionSha256Sum=<pinned sha256>
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
```

**4.2 `.gitignore` content (authoritative).**
```gitignore
# Gradle
.gradle/
build/
**/build/
!gradle/wrapper/gradle-wrapper.jar
!**/src/**/build/

# Android / local SDK
local.properties
.cxx/
captures/
*.apk
*.aab
*.ap_
*.dex

# Signing / secrets — never commit
*.keystore
*.jks
secrets.properties
keystore.properties

# IDE
.idea/
*.iml
.kotlin/

# OS
.DS_Store
Thumbs.db
```
Note the `!gradle/wrapper/gradle-wrapper.jar` negation: many default Android `.gitignore` templates ignore `*.jar`; we explicitly re-include the wrapper jar so FR-1 holds.

**4.3 README structure.** `android/README.md` sections, in order:
1. Overview + module map (`app -> feature-* -> core-*`).
2. Prerequisites (JDK 17, Android SDK 35, `ANDROID_HOME`/`local.properties`).
3. Clone & build.
4. Run on device/emulator.
5. Testing (unit + instrumented).
6. **Product flavors** (table).
7. **Base-URL switch** (table + override mechanism).
8. Troubleshooting (flaky dev host).

**4.4 Base-URL switch mechanism.** The README documents the convention the network layer (owned downstream by `core-network`) reads from: a `BuildConfig.API_BASE_URL` field whose value derives from the active flavor, with a **local override** via an untracked `local.properties` entry surfaced into `BuildConfig` by the app module. Example block the README shows:
```kotlin
// app/build.gradle.kts — illustrative (implemented in AND-002+/core-network)
val apiBaseUrl: String = providers.gradleProperty("API_BASE_URL")
    .orElse(localProperties.getProperty("apiBaseUrl") ?: "")
    .orElse(flavorDefaultBaseUrl)
    .get()
buildConfigField("String", "API_BASE_URL", "\"$apiBaseUrl\"")
```
README is explicit that AND-007 only *documents* this contract; the implementing wiring belongs to AND-002 and `core-network`.

## 5. API Contract

**N/A for this ticket.** AND-007 introduces no client/server interaction. It only *documents* that the runtime base URL defaults to the dev host `http://18.222.237.167:8000` and that the cookie-based session flow (`POST /ui/session/start` → MFA → `POST /ui/session/finalize` → `GET /ui/me`, with the `ui_csrf` cookie echoed as `X-CSRF-Token`) is implemented elsewhere. The HTTP client, cookie jar, CSRF handling, and `ApiResult<T>` mapping are owned by `core-network` (downstream of AND-001/AND-002). The README links to that future module rather than specifying contracts here.

## 6. Data & State Management

**N/A — no runtime data or state.** There is no Room cache, no DataStore, no `StateFlow<UiState>`, no ViewModel in this ticket. The only "state" is build-time configuration:

- **Tracked configuration (committed):** wrapper files, `.gitignore`, `README.md`, and (from AND-001) `gradle/libs.versions.toml` as the single source of dependency versions.
- **Untracked configuration (developer-local):** `local.properties` (SDK path + optional `apiBaseUrl` override) and `secrets.properties`/keystores — all excluded by FR-2's `.gitignore`.

The README's base-URL table is the canonical mapping a developer consults; DataStore-backed *runtime* base-URL switching, if ever added, is out of scope and would be a separate ticket.

## 7. Error Handling & Resilience

Resilience here is about the **clean-clone build experience**, not runtime failures:

- **Wrapper integrity:** `distributionSha256Sum` + `validateDistributionUrl=true` cause Gradle to fail fast if the downloaded distribution is tampered with or corrupted, rather than producing confusing downstream errors.
- **Missing SDK:** README's Troubleshooting section explains the `SDK location not found` error and the `local.properties`/`ANDROID_HOME` fix, since `local.properties` is intentionally untracked (FR-2).
- **Flaky dev host:** README explicitly warns that `http://18.222.237.167:8000` is an unreliable plaintext dev host; reads may take up to ~20s, connections may drop, and this is expected. It directs newcomers to the local-mock base URL when the dev host is down so a flaky backend is not mistaken for a broken build.
- **Cleartext traffic:** README notes that talking to the plaintext dev host requires a debug network-security config / `usesCleartextTraffic` (implemented downstream); the chore itself just documents the constraint.

## 8. Security & Privacy

- **No secrets in VCS:** FR-6 + `.gitignore` rules for `*.keystore`, `*.jks`, `secrets.properties`, `keystore.properties`, and `local.properties` prevent credential leakage. A grep-based DoD check (Section 15) enforces this on the committed tree.
- **Supply chain:** pinning `distributionSha256Sum` protects against a compromised Gradle CDN; the wrapper jar is reviewed once at commit time and thereafter immutable.
- **Cleartext disclosure:** README is explicit that the dev base URL is **plaintext HTTP** and therefore for development only; production builds MUST use HTTPS. This is a documentation control, not a code control, in this ticket.
- **No PII:** the README contains no credentials, tokens, or personal data; only a public dev IP already shared in project context.

## 9. Accessibility & i18n

**N/A — no user-facing UI.** This ticket ships developer documentation and build files, not app screens, so there are no Compose semantics, content descriptions, touch targets, RTL, or string-resource concerns. The `README.md` is written in clear English for contributors; localization of developer docs is out of scope. Accessibility/i18n obligations attach to the feature tickets that render UI (e.g. `feature-*` modules), not here.

## 10. Telemetry & Logging

**N/A — no runtime telemetry.** No analytics events, crash reporting, or log statements are introduced. The only observable signals are build-tool outputs:

- Gradle's own console/log output during `./gradlew` invocations.
- CI job logs for the clean-clone build (Section 11/15), which serve as the durable evidence that the acceptance criteria hold.

Runtime telemetry/logging conventions (structured logging, no-PII redaction) are owned by `core-*` infrastructure tickets.

## 11. Testing Strategy

Because there is no application code, testing is **build/process verification**, ideally automated in CI:

- **T-1 Clean-clone build (primary AC).** In a throwaway directory: `git clone <repo> && cd testlogon/android && ./gradlew --no-daemon :app:assembleDebug`. MUST succeed with no manual edits beyond providing an Android SDK. This is the executable form of the ticket's acceptance criterion.
- **T-2 Wrapper-only invocation.** `./gradlew --version` (and `gradlew.bat --version` on Windows CI) MUST report Gradle **8.9**, proving the pinned wrapper is used and no host `gradle` is required.
- **T-3 Tracked-files assertion.** `git ls-files android/ | grep gradle-wrapper.jar` MUST return the jar; `git ls-files` MUST also list `gradlew`, `gradlew.bat`, `gradle-wrapper.properties`, `.gitignore`, `README.md`.
- **T-4 Ignore-rules assertion.** After a build, `git status --porcelain android/` MUST be clean (no `build/`, `.gradle/`, `local.properties`, or APKs showing as untracked), proving `.gitignore` covers generated output.
- **T-5 Secret-leak scan.** `git ls-files android/ | grep -E '\.(jks|keystore)$|secrets\.properties|local\.properties'` MUST return nothing.
- **T-6 Executable bit.** `git ls-files -s android/gradlew` MUST show mode `100755`.
- **T-7 Wrapper integrity.** Corrupting/altering `distributionSha256Sum` MUST cause `./gradlew` to fail, confirming the checksum is enforced.
- **T-8 README link/command check.** A reviewer (or a markdown link-lint step) confirms every command in the README runs as written and internal links resolve.

A CI matrix job (Linux + Windows) running T-1, T-2, and T-4 is the recommended permanent guardrail against regressions.

## 12. Dependencies & Sequencing

- **Depends on:** **AND-001** — the wrapper, `.gitignore`, and README all wrap the Gradle skeleton (settings/build scripts + version catalog) that AND-001 produces. AND-007 cannot be merged before AND-001's files exist.
- **Blocks:** **AND-002** (app module config / `:app:assembleDebug`) and all subsequent module/CI tickets (AND-003 onward) that assume a committed wrapper and a green clean-clone build. CI pipeline tickets in particular rely on `./gradlew` existing in-repo.
- **Coordination:** the README's flavor table and base-URL switch describe contracts *implemented* by AND-002 and `core-network`; if those flavor names/`applicationId` suffixes change, this README must be updated in lockstep (tracked as a doc-follow-up on those tickets).
- **Sequencing:** AND-001 → **AND-007** → AND-002 → … . AND-007 is intentionally tiny and early so the rest of M1 develops against a reproducible baseline.

## 13. Risks & Open Questions

- **R-1 Wrapper jar diff noise.** The binary `gradle-wrapper.jar` is hard to review. *Mitigation:* generate via official `gradle wrapper`, pin the SHA-256, and note its provenance in the PR description.
- **R-2 Stale README drift.** Flavor names or base-URL keys could change downstream, making the README wrong. *Mitigation:* keep the flavor/base-URL details minimal and link to `core-network`/AND-002 as source of truth; add a doc check to those tickets.
- **R-3 Cleartext exception forgotten.** A newcomer may build successfully but get network failures against the plaintext dev host if the cleartext config (downstream) is missing. *Mitigation:* README Troubleshooting calls this out and points to the owning module.
- **R-4 Line endings / exec bit on Windows.** `gradlew` exec bit and CRLF can break on cross-platform checkouts. *Mitigation:* set git mode 100755, add a `.gitattributes` rule (`gradlew text eol=lf`, `*.bat text eol=crlf`) if needed.
- **Q-1 (open):** Are there multiple flavors at M1 (e.g. `dev`/`staging`/`prod`), or only a debug/release split with a single base URL? README must match whatever AND-002 lands; confirm with the AND-002 owner before merge.
- **Q-2 (open):** Should `.idea/` shared run configurations be tracked (some teams commit `.idea/runConfigurations/`)? Default here is to ignore all of `.idea/`.

## 14. Acceptance Criteria

- **AC-1 (source AC):** A clean `git clone` of `spannella/testlogon` followed by `cd android && ./gradlew :app:assembleDebug` (with only an Android SDK installed) builds successfully **with no extra setup** — no manual file creation beyond `local.properties` SDK path, which the README explains.
- **AC-2 (source AC):** `android/README.md` documents the **product flavors** (with resulting `applicationId` based on `com.testlogon.android`) **and** the **flaky-host base-URL switch** (dev plaintext host vs. local mock, plus the local override mechanism).
- **AC-3:** `gradlew`, `gradlew.bat`, `gradle-wrapper.jar`, and `gradle-wrapper.properties` are tracked in git; `--version` reports Gradle **8.9** (T-2).
- **AC-4:** After a full build, `git status` for `android/` is clean — no generated output is untracked (T-4).
- **AC-5:** No keystores, `secrets.properties`, or `local.properties` are tracked (T-5).
- **AC-6:** `gradlew` has executable mode `100755` and `distributionSha256Sum` is pinned and enforced (T-6, T-7).

## 15. Definition of Done

- All three artifacts (wrapper set, `android/.gitignore`, `android/README.md`) are committed on `android-port` and reviewed.
- CI clean-clone job (T-1) passes on Linux and Windows runners.
- T-2 through T-7 verification steps pass and are captured in the PR (paste or CI log links).
- README commands are confirmed runnable as written; internal links resolve (T-8).
- No secrets present in the tree; secret-scan (T-5) is clean.
- `gradle-wrapper.jar` provenance and pinned SHA-256 are noted in the PR description.
- Open questions Q-1/Q-2 are resolved (or explicitly deferred with sign-off) and the README reflects the resolution.
- PR links AND-001 as the satisfied dependency and references that AND-007 unblocks AND-002.

## 16. Citations & Assumption Audit

AND-007 is a build-hygiene **chore**: it ships no Kotlin, no UI, and makes no network calls. The only externally-verifiable technical claims are (a) the session/CSRF contract that Section 5 *describes as living elsewhere*, and (b) framework/toolchain version pins. Each is audited below against the authoritative OpenAPI index/spec and the frontend reference source.

1. **Claim (§5):** The runtime base URL defaults to the dev host and the session flow is `POST /ui/session/start` → MFA → `POST /ui/session/finalize` → `GET /ui/me`.
   - **VERDICT: Verified.** All three paths and methods exist exactly as written.
   - **SOURCE:** OpenAPI `POST /ui/session/start` (op=`ui_session_start_ui_session_start_post`, req=`UiSessionStartReq`, resp=`200:UiSessionStartResp`); `POST /ui/session/finalize` (op=`ui_session_finalize_ui_session_finalize_post`, req=`UiSessionFinalizeReq`); `GET /ui/me` (op=`ui_me_ui_me_get`). Frontend: `src/api/endpoints/auth.ts: sessionStart` → `api.post("/ui/session/start")`, `sessionFinalize` → `api.post("/ui/session/finalize")`. The intermediate MFA step is real — `src/api/endpoints/auth.ts` exposes `/ui/mfa/totp/verify`, `/ui/mfa/sms/verify`, `/ui/mfa/email/verify`, consistent with `SessionStartResp.required_factors` / `SessionStartResp.challenge_id`.

2. **Claim (§5):** Session is **cookie-based** with a `ui_csrf` cookie echoed as the `X-CSRF-Token` request header.
   - **VERDICT: Verified.** The web client reads the `ui_csrf` cookie and sets it verbatim as the `X-CSRF-Token` header on requests.
   - **SOURCE:** `src/api/client.ts` (lines ~167-170): `const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token", csrf);` and the doc comment "CSRF token from `ui_csrf` cookie".

3. **Claim (§5):** Request/response DTO shapes for the session flow are owned downstream (`core-network`); §5 itself specifies none.
   - **VERDICT: Verified (deferred-by-design) — and cross-checked.** For accuracy, the real shapes are: `SessionStartReq { challenge_context? }` → `SessionStartResp { auth_required, challenge_id?, required_factors[], session_id? }`; `SessionFinalizeReq { challenge_id, remember_device? }` → `SessionFinalizeResp { status:"ok"|"pending", session_id?, required_factors[], passed{} }`.
   - **SOURCE:** `src/api/types.ts: SessionStartReq/SessionStartResp/SessionFinalizeReq/SessionFinalizeResp` (lines 8-29); OpenAPI components.schemas `UiSessionStartReq`/`UiSessionStartResp`/`UiSessionFinalizeReq`.

4. **Claim (§5/§7):** Validation failures surface as a structured error body, not bare strings.
   - **VERDICT: Verified.** Every `/ui/session/*` op declares `422:HTTPValidationError`.
   - **SOURCE:** OpenAPI index lines for `POST /ui/session/start` and `POST /ui/session/finalize` (`resp=...;422:HTTPValidationError`); schema `HTTPValidationError` in `openapi.pretty.json` (`{ detail: [{ loc, msg, type }] }`).

5. **Claim (§2/§7/§8):** The dev backend `http://18.222.237.167:8000` is **plaintext HTTP** requiring a cleartext-permitted build.
   - **VERDICT: Unverified-assumption.** The IP/port and its plaintext nature come from project context, not from any source under `reference/`. The OpenAPI spec does not pin a server host, and cleartext config is an Android-runtime concern owned downstream. Treated as a documentation constraint only.
   - **SOURCE:** none in `reference/`; project-context value. Android cleartext behavior: `usesCleartextTraffic` / `network-security-config` (framework ref: https://developer.android.com/training/articles/security-config).

6. **Claim (§1/§3/§4.1):** Gradle wrapper pinned to **8.9** (`-bin`) with `distributionSha256Sum` + `validateDistributionUrl=true`.
   - **VERDICT: Unverified-assumption (framework choice, internally consistent).** Not verifiable from `reference/`; this is a toolchain decision inherited from AND-001. The wrapper-properties keys and the `gradle wrapper --gradle-version` / `--gradle-distribution-sha256-sum` flags are valid.
   - **SOURCE:** framework ref: https://docs.gradle.org/current/userguide/gradle_wrapper.html (wrapper task, checksum verification).

7. **Claim (§2):** Toolchain pins — JDK 17, AGP 8.7.3, Kotlin 2.0.21, KSP, compileSdk/targetSdk 35, minSdk 24.
   - **VERDICT: Unverified-assumption.** These describe AND-001's output and are not present in `reference/`. They must match whatever AND-001/AND-002 actually land; flagged for lockstep confirmation.
   - **SOURCE:** AND-001 (upstream ticket); framework refs: AGP/Kotlin/KSP release notes (https://developer.android.com/build/releases/gradle-plugin).

8. **Claim (§2/§4/§14):** Product flavors derive `applicationId` from base `com.testlogon.android`; base-URL surfaced via `BuildConfig.API_BASE_URL` overridable from untracked `local.properties`.
   - **VERDICT: Unverified-assumption.** Flavor names and the `BuildConfig` field are documented here but **implemented** by AND-002/`core-network`; nothing in `reference/` constrains them. This matches open question Q-1.
   - **SOURCE:** AND-002 / `core-network` (downstream, not yet authoritative); framework ref: https://developer.android.com/build/build-variants.

### Corrections made

- **None to factual content.** Every concrete, source-checkable claim (session paths, HTTP methods, CSRF header derivation, 422 error shape) was confirmed accurate against the OpenAPI index and the frontend reference; no path/method/field corrections were required.
- **Frontmatter:** `status` changed `draft → reviewed`; added `reviewed_on: 2026-06-06`.
- **Precision added (non-corrective):** Audit item 3 records the exact session DTO field names from `src/api/types.ts` so downstream `core-network` work has a verified reference, even though §5 intentionally defers them.

### Open assumptions

- **Dev host plaintext (item 5):** `http://18.222.237.167:8000` and its cleartext requirement are project-context facts with no corroborating source under `reference/`; cannot be verified here.
- **Toolchain/version pins (items 6, 7):** Gradle 8.9, AGP 8.7.3, Kotlin 2.0.21, SDK 35/24 originate from AND-001 and are not in the reference sources; they must be reconciled against AND-001's committed `gradle/libs.versions.toml` and wrapper at merge time.
- **Flavors & base-URL wiring (item 8):** Flavor set, `applicationId` suffixes, and the `BuildConfig.API_BASE_URL` mechanism are owned by AND-002/`core-network` (open question Q-1); the README must be updated in lockstep if those change.

## 17. Test Plan

Because AND-007 ships build/config/text artifacts (no runtime code), most cases are build/process verification rather than unit/Compose tests. Cases are sized to the chore.

- **TC-AND-007-01 — Clean-clone build succeeds**
  - **Type:** integration (CI, Linux + Windows matrix)
  - **Preconditions:** Throwaway working dir; only an Android SDK 35 + JDK 17 installed; no host `gradle`; AND-001 + AND-007 merged on `android-port`.
  - **Steps:** `git clone <repo>`; `cd testlogon/android`; create `local.properties` with `sdk.dir` per README; `./gradlew --no-daemon :app:assembleDebug` (and `gradlew.bat` on Windows).
  - **Expected:** Build succeeds; a debug APK is produced; no manual edits beyond the documented `local.properties` SDK path.
  - **Traces:** AC-1.

- **TC-AND-007-02 — Wrapper reports pinned Gradle version**
  - **Type:** contract (build-tool) / instrumented (CI)
  - **Preconditions:** Repo cloned per TC-01; no host `gradle` on PATH.
  - **Steps:** Run `./gradlew --version`; on Windows CI run `gradlew.bat --version`.
  - **Expected:** Output reports Gradle **8.9**; the wrapper (not a host install) drives the build.
  - **Traces:** AC-3.

- **TC-AND-007-03 — Wrapper files are tracked**
  - **Type:** unit (repo assertion)
  - **Preconditions:** Repo cloned.
  - **Steps:** `git ls-files android/` and assert presence of `gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`, `gradle/wrapper/gradle-wrapper.properties`, `.gitignore`, `README.md`.
  - **Expected:** All listed files appear; notably `gradle-wrapper.jar` is tracked (the `!gradle/wrapper/gradle-wrapper.jar` negation works).
  - **Traces:** AC-3.

- **TC-AND-007-04 — Ignore rules keep tree clean after build**
  - **Type:** integration
  - **Preconditions:** TC-01 build completed.
  - **Steps:** `git status --porcelain android/`.
  - **Expected:** Empty output — no `build/`, `.gradle/`, `local.properties`, `.cxx/`, `captures/`, `*.apk`/`*.aab` shown as untracked.
  - **Traces:** AC-4.

- **TC-AND-007-05 — No secrets tracked (security)**
  - **Type:** unit (secret-leak scan) / security
  - **Preconditions:** Repo cloned.
  - **Steps:** `git ls-files android/ | grep -E '\.(jks|keystore)$|secrets\.properties|keystore\.properties|local\.properties'`.
  - **Expected:** No matches. No keystore, `secrets.properties`, `keystore.properties`, or `local.properties` is tracked.
  - **Traces:** AC-5.

- **TC-AND-007-06 — gradlew executable bit**
  - **Type:** unit (repo assertion) / permission
  - **Preconditions:** Repo cloned.
  - **Steps:** `git ls-files -s android/gradlew`.
  - **Expected:** Mode is `100755` (executable bit set), so POSIX checkouts can run `./gradlew` without `chmod`.
  - **Traces:** AC-6.

- **TC-AND-007-07 — Wrapper checksum is enforced**
  - **Type:** integration (negative / supply-chain)
  - **Preconditions:** Clean Gradle user home (no cached 8.9 dist); `distributionSha256Sum` pinned in `gradle-wrapper.properties`.
  - **Steps:** Temporarily corrupt `distributionSha256Sum` (one char) in a scratch copy; run `./gradlew --version`.
  - **Expected:** Gradle fails fast with a checksum-mismatch error and does not proceed; restoring the value fixes it. Confirms `distributionSha256Sum` + `validateDistributionUrl=true` are active.
  - **Traces:** AC-6.

- **TC-AND-007-08 — README documents flavors and applicationId**
  - **Type:** manual (doc review)
  - **Preconditions:** `android/README.md` present.
  - **Steps:** Read the Product Flavors section; cross-check each listed flavor's resulting `applicationId` against base `com.testlogon.android`.
  - **Expected:** Every flavor and its `applicationId` (suffix) is listed; a reader can predict the installed package name. (If AND-002 has not finalized flavors, the section is marked provisional per Q-1.)
  - **Traces:** AC-2.

- **TC-AND-007-09 — README documents base-URL switch incl. flaky-host/offline path**
  - **Type:** manual (doc review)
  - **Preconditions:** README present.
  - **Steps:** Read the Base-URL Switch + Troubleshooting sections; verify they cover (a) dev plaintext host `http://18.222.237.167:8000`, (b) local-mock fallback when the dev host is down/offline, (c) the untracked `local.properties` `apiBaseUrl` override, and (d) the cleartext-traffic requirement + ~20s timeout warning.
  - **Expected:** All four are present; offline/flaky guidance steers newcomers to the mock so backend flakiness is not mistaken for a build failure.
  - **Traces:** AC-2.

- **TC-AND-007-10 — README commands run as written & links resolve**
  - **Type:** manual / instrumented (markdown link-lint + command smoke)
  - **Preconditions:** README present; repo cloned.
  - **Steps:** Execute each copy-pasteable command (prereqs, build, run, unit test, instrumented test); run a markdown link checker over internal links.
  - **Expected:** Every command succeeds (or fails only for documented external reasons like SDK absence); all internal links resolve.
  - **Traces:** AC-1, AC-2.

- **TC-AND-007-11 — Cross-platform line endings / exec bit (Windows)**
  - **Type:** integration (Windows CI runner)
  - **Preconditions:** `.gitattributes` rules (if added) for `gradlew text eol=lf`, `*.bat text eol=crlf`; Windows runner.
  - **Steps:** Fresh clone on Windows; run `gradlew.bat :app:assembleDebug`; verify `gradlew` retains LF and the bat file CRLF.
  - **Expected:** Build runs on Windows; no CRLF corruption of `gradlew`; addresses risk R-4.
  - **Traces:** AC-1, AC-3.

### Coverage matrix

| Acceptance Criterion (§14) | Covered by |
| --- | --- |
| AC-1 (clean-clone build, no extra setup) | TC-AND-007-01, TC-10, TC-11 |
| AC-2 (README: flavors + base-URL switch) | TC-AND-007-08, TC-09, TC-10 |
| AC-3 (wrapper tracked; `--version` = 8.9) | TC-AND-007-02, TC-03, TC-11 |
| AC-4 (clean `git status` after build) | TC-AND-007-04 |
| AC-5 (no secrets/local.properties tracked) | TC-AND-007-05 |
| AC-6 (gradlew 100755; SHA-256 pinned & enforced) | TC-AND-007-06, TC-07 |
