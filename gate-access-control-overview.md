# Gate Access Control — Detailed Visual Overview

**BearMGMT ↔ OpenTech IoE integration — the full design, explained with diagrams.**

Self-storage properties have physical gates with keypads. BearMGMT issues each tenant a unique PIN (gate code); the gate hardware is run by a vendor platform — **OpenTech Alliance IoE** — that Bear drives over REST and listens to via webhooks. **Bear decides, OpenTech executes at the gate.**

> Companion to the full design doc: [gate-access-control-architecture.md](gate-access-control-architecture.md) (adds security deep-dive, runbook, testing strategy, phase plan).

**Contents:** 1. Tenant journey · 2. Big picture · 3. Component view · 4. Mapping & onboarding · 5. Lifecycles · 6. Database in detail · 7. Gate-code security · 8. API essentials · 9. All sequence diagrams · 10. Open points

---

## 1. The Tenant's Journey in One Picture

```mermaid
flowchart LR
    A([Move-In]) -->|"code generated + visitor created"| B[Code works at gate]
    B -->|"payment overdue"| C[Code rejected - delinquent]
    C -->|"pays up"| B
    B -->|"unit transfer"| D[New code on new unit NOW<br/>old code dies on move-out date]
    B -->|"move-out"| E([Code revoked<br/>unit vacant])
    C -->|"move-out"| E
    D --> E

    style A fill:#2e7d32,color:#fff
    style B fill:#388e3c,color:#fff
    style C fill:#e65100,color:#fff
    style D fill:#1565c0,color:#fff
    style E fill:#616161,color:#fff
```

Every arrow above is one Bear command that (1) commits to Bear's database first, then (2) calls OpenTech — never the other way round.

---

## 2. The Big Picture

```mermaid
flowchart LR
    subgraph Bear["🐻 BearMGMT"]
        API[API<br/>staff + tenant endpoints<br/>+ webhook receiver]
        DB[(PostgreSQL<br/>mappings · credentials<br/>work queue · events)]
        WK[Worker<br/>executes queued vendor calls<br/>+ nightly event backfill]
        API --> DB
        WK --> DB
    end
    subgraph OT["🏢 OpenTech IoE"]
        AC[Access Control API<br/>facilities · units · visitors]
        EV[Event API<br/>history]
        SNS[Webhooks<br/>real-time push]
    end
    GATE["🚪 Gate keypad"]

    API -->|commands| AC
    WK -->|retries + scheduled| AC
    WK -->|backfill| EV
    SNS -->|access events| API
    AC -.->|config push| GATE
    GATE -.->|every PIN entry| SNS
```

**Four rules carry the design:**

| # | Rule | Why |
|---|---|---|
| 1 | 🔌 **Provider port** — business logic talks to an `IGateAccessProvider` interface, OpenTech is just an adapter behind it | Swap or add vendors later without touching business code — vendor choice is made **per property** |
| 2 | 💾 **DB first, vendor second** — intent committed locally before any vendor call | A vendor-side change with no Bear record would be an invisible security hole. A Bear-side pending row is visible and retryable |
| 3 | 📋 **Work-queue table** (`gate_operations`) — every vendor call is a row the Worker executes, retries with backoff, dead-letters + alerts | Survives restarts and deploys. Future-dated rows = scheduled revocations (transfers). Queryable, cancellable, auditable |
| 4 | 👁 **Events are observational** — webhooks feed dashboards/alerts, never business decisions | A missed webhook can't corrupt state. A nightly poll closes any gaps |

---

## 3. Component View (who lives where)

Clean Architecture holds: Api and Worker depend on Application; Infrastructure implements Application's interfaces; no vendor type ever leaves Infrastructure.

```mermaid
flowchart TB
    subgraph Api["BearMGMT.Api"]
        EP["Gate endpoints<br/>/api/v1/admin/gates/*<br/>/api/v1/client/gates/my-code"]
        WH["Webhook endpoint<br/>/api/v1/webhooks/gate/opentech/:configId<br/>AllowAnonymous + verification chain"]
    end
    subgraph App["BearMGMT.Application"]
        CMD[Commands & queries<br/>one vertical slice per operation]
        PORT[Ports:<br/>IGateAccessProvider<br/>IGateProviderFactory<br/>IGateWebhookProcessor<br/>IGateCodeCipher]
        REPO[IGate*Repository interfaces]
    end
    subgraph Infra["BearMGMT.Infrastructure"]
        OTA[OpenTech adapter<br/>speaks vendor API]
        TOK[GateTokenProvider<br/>token cache per config<br/>password grant only]
        SNSP[SNS webhook processor<br/>verify + normalize events]
        SEC[Secrets Manager resolver]
        KMS[KMS envelope cipher]
        EFR[EF Core repositories]
    end
    subgraph Worker["BearMGMT.Worker"]
        DISP[Operation dispatcher<br/>30s poll · SKIP LOCKED<br/>retry · dead-letter]
        BKF[Nightly event backfill]
        SWEEP[Event processing sweep]
    end
    subgraph AWS["AWS"]
        SM[(Secrets Manager<br/>vendor credentials)]
        KK[(KMS<br/>code encryption keys)]
        PG[(Aurora PostgreSQL)]
    end
    subgraph Vendor["OpenTech"]
        AUTH[Auth API]
        ACA[Access Control API]
        EVA[Event API]
        SNS2[SNS webhooks]
    end

    EP --> CMD
    WH --> CMD
    CMD --> PORT
    CMD --> REPO
    PORT -.->|implemented by| OTA
    PORT -.->|implemented by| SNSP
    REPO -.->|implemented by| EFR
    OTA --> TOK --> AUTH
    OTA --> ACA
    OTA --> EVA
    OTA --> SEC --> SM
    PORT -.->|cipher| KMS --> KK
    EFR --> PG
    DISP --> PORT
    BKF --> PORT
    SWEEP --> PG
    SNS2 --> WH
```

Key implementation notes: three named `HttpClient`s (auth / control / event hosts — they are **separate hosts** at OpenTech), correlation-ID propagated on every outbound call, standard resilience handler (retry/circuit-breaker) inherited globally, all vendor failures surface as `ExternalServiceException` → HTTP 502.

---

## 4. BearMGMT ↔ OpenTech Mapping & Onboarding

### 4.1 The mapping

```mermaid
flowchart LR
    subgraph B["BearMGMT world"]
        ORG[🏛 Organization]
        PROP[🏘 Property]
        UNIT[📦 Unit]
        TEN[👤 Tenant on unit]
        ORG --> PROP --> UNIT --> TEN
    end
    subgraph M["Mapping tables in Bear DB"]
        M1[gate_provider_configs<br/>provider connection, registered by DevOps,<br/>secrets → Secrets Manager, admin key = selector]
        M2[gate_facility_mappings<br/>1 : 1]
        M3[gate_unit_mappings<br/>1 : 1]
        M4[gate_access_credentials<br/>code + visitorId + status]
    end
    subgraph O["OpenTech world"]
        ACC[🔑 Account<br/>API credentials]
        FAC[🏭 Facility<br/>facilityId]
        VUN[📦 Unit<br/>unitId]
        VIS[🎫 Visitor<br/>visitorId + accessCode]
        ACC --> FAC --> VUN --> VIS
    end
    ORG === M1 === ACC
    PROP === M2 === FAC
    UNIT === M3 === VUN
    TEN === M4 === VIS
```

**Dependency rules (who must exist first):**

| Thing | Created by | Rule |
|---|---|---|
| Organization / Property in Bear | Bear only | **No OpenTech prerequisite ever** — gate integration is opt-in later, and **unit creation is never blocked** by missing gate config (client-confirmed) |
| OpenTech account + credentials | Vendor (commercial step) | Needed only when the org wants gate integration |
| Facility | **Bear's Super Admin team, manually, in OpenTech's own portal — no create API exists** | Created **first**, with `propertyNumber` set to equal the Bear property's Code — this is what makes Bear-side linking fully automatic (§4.3) |
| Unit (vendor side) | Either — Bear **can** create via API | Must be mapped before the **first move-in** on that unit; the manual Sync button handles it |
| Visitor | Bear via API at move-in, or via Sync (backfill for pre-existing tenants) | Vendor assigns `visitorId` — no external key, capture it instantly |

**Provider setup is property-first, and the admin's API key is a *selector*, never a credential entry.** ALL secrets are **pre-provisioned in AWS Secrets Manager by DevOps** when the organization's vendor account is set up: the *platform secret* (Bear's `clientId`/`clientSecret` + the three base URLs, one per provider + environment) and the *account secret* (`apiKey` + `apiSecret` per OpenTech account), each registered as a **provider connection** row (`gate_provider_configs`) under the organization. **No secret material ever passes through an admin screen.**

To map a property, the Org Admin opens its gate settings, chooses the provider, and enters **only the API key**. Bear computes the key's **fingerprint** (a keyed hash) and looks it up among the org's provisioned connections:

- **Match found** → Bear loads the secrets from AWS, verifies with a live vendor call, and connects the property to that account. The admin never saw the `apiSecret` — and the key alone cannot authenticate; the secret half stays in AWS.
- **No match** → nothing is created; the admin gets a clear message: *"No provisioned gate account matches this key — contact support/DevOps."*

Entering the same key on five properties connects all five to the **same** connection: one secret, one token cache, one rotation point.

Consequences: an organization can run **multiple providers and multiple vendor accounts at the same time** — each property simply uses whatever connection its keys resolve to. One property = one provider at a time (DB-enforced). Whether vendor accounts are owned per organization or centrally by Bear (reseller model) remains business decision **C-1** (§10) — the property-first flow works identically either way.

### 4.2 Property onboarding — one wizard, everything in property settings

| Step | What the admin does | What Bear does |
|---|---|---|
| 1️⃣ Choose provider + enter API key (selector) | On the property's gate settings: picks the provider (OpenTech), enters **only the API key** — never the secret; all credentials were already provisioned in **AWS Secrets Manager by DevOps** | Computes the key fingerprint and looks it up among the org's provisioned connections. **Match** → loads platform + account secrets from AWS, verifies live (`GET /facilities` — a stale key fails **here**, not weeks later at a move-in), connects the property. **No match** → nothing created, clear error: *"no provisioned gate account matches this key — contact support/DevOps"* |
| 2️⃣ Link facility | **Nothing — fully automatic** (client-confirmed) | Bear's Super Admin already created the OpenTech property with `propertyNumber` = Bear's property Code (§4.1), so Bear calls `GET /facilities/detail?propertyNumber=` and links on the **exact match**, no click needed. **Fallback only:** if no exact match exists (legacy data, typo), a manual-resolution screen appears — pick from a dropdown, same sanity checks as before |
| 3️⃣ Sync units (manual button) | Clicks Sync whenever needed, resolves the review list | Match by `unitNumber` → store vendor `unitId`; **create** vendor-side units missing for Bear units; **push access codes** for units with an active Bear credential but no vendor visitor yet (backfills tenants who moved in *before* gate integration was configured); **report** vendor units unknown to Bear (never auto-import). **Unit-level only — there's no property-level sync**, since properties always originate in OpenTech |
| 4️⃣ Backfill events | — | Pages the vendor Event API into `gate_events` (deduped), sets the sync cursor |
| 5️⃣ Real-time events | — | SNS webhook subscription per vendor account (provisioning process = vendor question V-1); Bear auto-completes the SNS handshake. Already live if another property reused the same connection |

After step 5 the property shows *Gate integration: active* and daily operations are fully automatic. (Full sequence diagram in §9.2.)

**Prerequisite (step 0, before any of the above):** Bear's Super Admin team creates the property directly in OpenTech's own portal — there's no create-facility API — and deliberately sets its `propertyNumber` to equal the Bear property's Code. That single convention is what turns step 2️⃣ from a manual dropdown into a zero-click automatic match.

**Access profile, MVP scope (client-confirmed):** every visitor is created with the vendor's **single default profile** ("24-hour" / "All Access") — there's no admin UI to assign a different time group or access area per tenant. Multi-profile, time-window-restricted access is a future phase.

**Rotation is entirely DevOps-side:** all secret contents (platform *and* account) are updated directly in Secrets Manager by DevOps — admins never touch them; Bear's caches evict on the next persistent 401 and the new values flow with no restart. If the API key itself changes, DevOps also updates the connection's fingerprint. (An org-level read-only "gate connections" list exists purely for visibility — which properties share which connection — it is not a setup surface.)

---

## 5. Lifecycles

### 5.1 Credential lifecycle — `gate_access_credentials.status`

```mermaid
stateDiagram-v2
    [*] --> pending_activation : move-in (code saved locally)
    pending_activation --> active : vendor create OK
    pending_activation --> failed : retries exhausted → staff alert
    failed --> pending_activation : staff retry
    active --> suspended : delinquent → gate locked
    suspended --> active : paid → gate unlocked
    active --> revoke_scheduled : transfer (future-dated)
    revoke_scheduled --> active : transfer cancelled
    revoke_scheduled --> revoke_pending : move-out date reached
    active --> revoke_pending : move-out
    suspended --> revoke_pending : move-out
    revoke_pending --> revoked : vendor confirmed
    revoked --> [*]
```

| Business event | Vendor call | Effect at the gate |
|---|---|---|
| Move-in | `POST …/visitors` | Code works, unit → Rented |
| Delinquent | `POST …/visitors/{vid}/disable` (empty body) | Code rejected, record kept |
| Paid | `POST …/visitors/{vid}/enable` (empty body) | Code works again |
| Move-out | `POST …/units/{uid}/vacate` (empty body) | All unit codes dead, unit → Vacant |
| Transfer | new visitor now + **scheduled** vacate later | Both codes live during overlap |

### 5.2 Operation lifecycle — `gate_operations.status` (the work queue)

```mermaid
stateDiagram-v2
    [*] --> scheduled : future-dated (transfer revocation)
    [*] --> pending : immediate
    scheduled --> pending : scheduled_for reached
    scheduled --> cancelled : transfer cancelled or re-dated
    pending --> in_progress : Worker claims (SKIP LOCKED)
    in_progress --> succeeded : vendor OK (409 counts as OK)
    in_progress --> failed : transient error → backoff
    failed --> in_progress : Worker retries (~5 attempts, client-confirmed)
    failed --> dead : attempts exhausted or 4xx → 🚨 staff alert
    dead --> pending : staff manual retry
    succeeded --> [*]
    cancelled --> [*]
```

Retry policy: the HTTP layer already retries 5xx quickly (2s/4s/8s); the dispatcher then re-schedules with exponential backoff (max 30 min apart, **~5 attempts** — client-confirmed policy). Revocations that stay failed past **15 minutes** raise the fail-open alert regardless of attempt count — a tenant may still have physical access, which staff can end manually at the vendor console (plus the property's `failure_notification_email` if configured) while Bear keeps retrying.

---

## 6. Database in Detail (7 tables)

All tables: `uuid` PKs (`gen_random_uuid()`), snake_case, org-scoped (`organization_id` + tenant query filters), audit columns + soft delete — except `gate_events`, which is append-only like `audit_logs`.

### 6.1 ER overview

```mermaid
erDiagram
    organizations ||--o{ gate_provider_configs : "1..N cards"
    gate_provider_configs ||--o{ gate_facility_mappings : owns
    properties ||--o| gate_facility_mappings : "1:1"
    gate_facility_mappings ||--o{ gate_unit_mappings : contains
    units ||--o| gate_unit_mappings : "1:1"
    gate_facility_mappings ||--o{ gate_access_credentials : scopes
    users ||--o{ gate_access_credentials : tenant
    gate_encryption_keys ||--o{ gate_access_credentials : "dek_id"
    gate_access_credentials ||--o{ gate_operations : "acted on by"
    gate_provider_configs ||--o{ gate_events : receives
    gate_access_credentials ||--o{ gate_events : "resolved to"

    gate_provider_configs {
        uuid organization_id
        text provider_type "open_tech (extensible)"
        text environment "sandbox|production"
        text secret_ref "Secrets Manager ARN only"
        text api_key_fingerprint "reuse-detection hash"
        text webhook_token "random, in webhook URL"
        jsonb settings "code length, defaults"
        boolean is_enabled
    }
    gate_facility_mappings {
        uuid provider_config_id FK
        uuid property_id "UNIQUE"
        text external_facility_id
        text external_property_number
        text status "linked|sync_error|disabled"
        int code_length "4-12, per property"
        text failure_notification_email
        timestamptz last_event_sync_at "poll cursor"
    }
    gate_unit_mappings {
        uuid facility_mapping_id FK
        uuid unit_id "UNIQUE"
        text external_unit_id
        text external_unit_number
        text sync_status "pending|synced|error"
    }
    gate_access_credentials {
        uuid tenant_user_id FK
        uuid unit_id FK
        uuid lease_id "nullable - reserved"
        text external_visitor_id
        bytea access_code_ciphertext
        bytea access_code_nonce
        uuid dek_id FK
        bytea access_code_hmac
        text status "7-state machine"
        boolean is_gate_restricted
        timestamptz last_access_at
    }
    gate_encryption_keys {
        uuid organization_id
        bytea wrapped_dek "KMS-wrapped"
        text kms_key_arn
        timestamptz retired_at
    }
    gate_events {
        text external_event_id "dedup"
        int event_type_raw
        text event_type "canonical"
        timestamptz occurred_at
        text source "webhook|poll"
        jsonb raw_payload
        text processing_status
    }
    gate_operations {
        text operation_type
        jsonb payload "no plaintext codes"
        text trigger_source
        text status "7-state machine"
        timestamptz scheduled_for
        text idempotency_key "UNIQUE"
        int attempt_count
        timestamptz next_attempt_at
    }
```

### 6.2 `gate_provider_configs` — a provider connection (registered by DevOps at account provisioning)

Rows are **registered by DevOps** when the organization's vendor account is provisioned (secret stored + row created with its ARN and key fingerprint). The admin UI never creates or modifies these rows — an admin's API-key entry on a property only **looks them up**.

| Column | Meaning |
|---|---|
| `organization_id` | Owning org (tenant isolation) — **0..N connections per org**, one per vendor account |
| `provider_type` | Vendor discriminator, CHECK `('open_tech')` today — a new vendor = new enum value + new adapter |
| `display_name`, `environment` | Set at provisioning (editable), sandbox/production |
| `secret_ref` | **AWS Secrets Manager ARN only** — the account secret `{ apiKey, apiSecret }`, **provisioned and rotated by DevOps**. Base URLs + `clientId`/`clientSecret` live in a separate **platform secret** per provider + environment, also DevOps-managed. Credentials never in the DB, never on any admin screen |
| `api_key_fingerprint` | Keyed hash (HMAC) of the API key, stored at provisioning — **how an admin's entered key selects this connection**. UNIQUE `(organization_id, provider_type, api_key_fingerprint)`. The key itself is not recoverable from it |
| `webhook_token` | Random 256-bit token in the webhook URL — cheap first-line filter before SNS signature checks |
| `allowed_topic_arns` | SNS topic allow-list |
| `settings` (jsonb) | Default `timeGroupId`/`accessProfileId` (default: **omit** — MVP always uses the single default profile; the POC's literal `0` is vendor question V-7), revocation-mode override. Code length is **not** here — it's per-property (§6.3) |
| `is_enabled` | Off = stop dispatching + reject webhooks for every property on this connection |

### 6.3 `gate_facility_mappings` — property ↔ facility (1:1)

| Column | Meaning |
|---|---|
| `property_id` | **UNIQUE** — one gate system per property, ever |
| `provider_config_id` | Which card (→ which account/vendor) this property uses |
| `external_facility_id`, `external_property_number` | Vendor `facilityId` + `propertyNumber` — the latter is now a **deterministic match key** (Super Admin sets it = Property.Code, §4.1), not just a hint |
| `status` | `linked` / `sync_error` (403 = rotated credentials, **or** no exact `propertyNumber` match found) / `disabled` (staged during vendor switch) |
| `code_length` | **Configurable 4–12 per property** (client-confirmed; default 6) — lives here, not on the provider config, since one vendor account can serve multiple properties with different lengths |
| `failure_notification_email` | Client-confirmed MVP feature — alerts this address (plus the in-app indicator) when a sync operation for this property dead-letters |
| `last_synced_at`, `last_event_sync_at`, `last_error` | `last_event_sync_at` is the polling-backfill cursor |

Also `UNIQUE (provider_config_id, external_facility_id)` — a facility can be linked to only one property.

### 6.4 `gate_unit_mappings` — unit ↔ vendor unit (1:1)

| Column | Meaning |
|---|---|
| `unit_id` | **UNIQUE** — Bear unit |
| `facility_mapping_id` | Parent facility link |
| `external_unit_id` | Vendor numeric `unitId` — **required by every visitor call**; no row = no move-in |
| `external_unit_number` | Vendor `unitNumber` string — the sync matching key |
| `sync_status` | `pending` / `synced` / `error` (+ `last_error`, index on `(facility_mapping_id, sync_status)` for reconciliation) |

### 6.5 `gate_access_credentials` — who holds which code (the core aggregate)

| Column | Meaning |
|---|---|
| `tenant_user_id`, `unit_id`, `facility_mapping_id` | Who, where |
| `lease_id` *(nullable, no FK yet)* | Reserved — binds to the Lease module in Phase 2 (deliberate schema debt, cheaper than re-keying later) |
| `external_visitor_id` | Vendor `visitorId`, captured from the create response — **the only correlation key that exists**. CHECK: must be present once status = `active` |
| `access_code_ciphertext` + `access_code_nonce` + `dek_id` | The gate code, AES-256-GCM encrypted under a per-org data key (§7) |
| `access_code_hmac` | Keyed hash (separate key) → powers the uniqueness index below |
| `status` | 7-state machine (§5.1) |
| `is_gate_restricted` | Gate-side flag of the 2×2 matrix — portal lockout is deliberately a *separate* state elsewhere; when set, the tenant portal **withholds the code server-side** |
| `activated_at`, `revoked_at`, `revoke_reason`, `last_access_at` | Timeline + "last gate entry" (fed by events) |

**The constraint that makes codes unique per facility** (a keypad identifies a person by code alone):

```sql
CREATE UNIQUE INDEX ux_gate_credentials_code_per_facility
  ON gate_access_credentials (facility_mapping_id, access_code_hmac)
  WHERE status IN ('pending_activation','active','suspended','revoke_scheduled','revoke_pending')
    AND deleted_at IS NULL;
```

Revoked rows keep their (encrypted) code for audit but release it for reuse — the partial index only guards *live* credentials.

### 6.6 `gate_encryption_keys` — KMS envelope keys

| Column | Meaning |
|---|---|
| `organization_id` | One **active** key per org (partial unique where `retired_at IS NULL`) |
| `wrapped_dek` | Data key wrapped by the KMS master key — plaintext key exists only in process memory |
| `kms_key_arn`, `retired_at` | Which master key, rotation support (old rows still decrypt via their own `dek_id`) |

### 6.7 `gate_events` — append-only event stream

| Column | Meaning |
|---|---|
| `external_event_id` | **UNIQUE per config** — webhook and poll both insert with `ON CONFLICT DO NOTHING`, so the same event lands once no matter the path |
| `event_type_raw` → `event_type` | Vendor enum (18, 17, 15…) → canonical (`access_granted`, `access_denied_delinquent`, `access_denied_invalid_code`, …, `unknown`) |
| `credential_id`, `facility_mapping_id` | Resolved during async processing (nullable at ingest) |
| `code_entered_masked` | If the vendor sends the entered code, Bear stores it **masked** (`****34`) |
| `raw_payload` (jsonb) | Full vendor event, kept for forward compatibility |
| `source`, `processing_status`, `received_at`, `processed_at` | `webhook`/`poll`; `pending → processed/skipped/error` drives the sweep |

Indexes: BRIN on `occurred_at` (big, time-ordered), btree `(facility_mapping_id, occurred_at DESC)` for the events screen, partial on `pending`. Append-only trigger like `audit_logs`; monthly partitioning is a Phase 3 step.

### 6.8 `gate_operations` — outbox + scheduler in one table

| Column | Meaning |
|---|---|
| `operation_type` | `create_visitor`, `update_visitor_code`, `suspend_visitor`, `reinstate_visitor`, `remove_visitor`, `vacate_unit`, `create_unit`, `sync_units`, `backfill_events` |
| `payload` (jsonb) | Canonical request snapshot — **never contains the plaintext code** (executor decrypts from the credential row at send time) |
| `trigger_source` | `move_in` / `move_out` / `transfer_scheduled` / `delinquency` / `manual` / `reconciliation` / `onboarding` |
| `status` | 7-state machine (§5.2) |
| `scheduled_for` | `now()` for immediate work; **future = scheduled revocation**, computed in the property's timezone, re-datable/cancellable until claimed |
| `idempotency_key` | UNIQUE — e.g. `revoke:{credentialId}:{moveOutDate}`; a re-submitted command lands on the existing row |
| `attempt_count`, `next_attempt_at`, `last_error` | Retry machinery (sanitized errors) |
| `correlation_id`, `completed_at` | End-to-end tracing |

Dispatcher hot-path indexes: partial `(next_attempt_at)` for pending/failed, partial `(scheduled_for)` for scheduled; claims use `FOR UPDATE SKIP LOCKED` so multiple Worker instances never collide.

Why one merged table: a scheduled revocation is just an operation whose time hasn't come — one dispatcher, one retry/dead-letter policy, one ops dashboard, instead of duplicating all three.

---

## 7. Gate-Code Security (why encrypted, never hashed, never logged)

```mermaid
flowchart LR
    G[🎲 Generate<br/>4-12 digits per property, CSPRNG<br/>reject 111111, 123456, unit no.] --> E[🔒 Encrypt<br/>AES-256-GCM<br/>per-org key via KMS]
    G --> H[#️⃣ HMAC<br/>separate key]
    E --> S[(credential row:<br/>ciphertext + nonce + dek_id + hmac)]
    H --> S
    S -->|decrypt only for| V[📤 vendor create call]
    S -->|decrypt only for| P[🖥 staff detail screen +<br/>tenant portal display]
    S -.->|never| L[🚫 logs · audit JSON ·<br/>work queue · URLs · events]

    style L fill:#b71c1c,color:#fff
```

- **Why not hashed:** OpenTech never returns the code on any read (`code: null`), and the tenant portal must display it — Bear's copy is the only recoverable one. Hashing is functionally impossible; plaintext is unacceptable; encryption with controlled, audited reveal is the only fit.
- **Why not pgcrypto:** the key would travel inside SQL text (leaks into DB logs / `pg_stat_statements`). App-level AES + KMS envelope keeps keys off the DB tier entirely.
- **Uniqueness without decryption:** the HMAC column (separate key) feeds the per-facility unique index — collision on insert → regenerate (cap 10, then fail loudly per TM-009's failure-message requirement).
- **Every reveal is audited** (`gate_code.revealed`, actor + portal, never the value). When `is_gate_restricted` is true, the tenant endpoint **omits the code field from the response entirely** — struck-through display is driven by a flag, not a hidden value (TP-004's server-side withholding).
- **A third, "zeroth" state (client-confirmed):** if the property has **no gate system configured at all**, the entire gate-code section is **absent from the tenant UI** — not empty, not struck-through, just not there. This is checked *before* the restricted/active logic above, since it's a different condition (no integration vs. integration-but-restricted).
- Regeneration: new code in the local transaction → `update_visitor_code` operation; if the vendor can't update in place (open question V-2), fallback is remove + recreate visitor (new `visitorId` persisted).
- ⚠ **Vendor conflict, flagged (V-10):** the vendor guide documents `accessCode` as max **10 digits**, but the client wants **up to 12**. Properties configured for 11–12 may be rejected by OpenTech at move-in — confirm with vendor support before relying on the top of the range.

---

## 8. API Essentials (QA-validated)

```mermaid
flowchart LR
    T["1️⃣ POST /auth/token<br/>password grant<br/>cache ~1h, reuse until 401/expiry"] --> U["2️⃣ POST /facilities/{fid}/units<br/>{unitNumber}<br/>→ store unit.id"]
    U --> V["3️⃣ POST /facilities/{fid}/visitors<br/>{isTenant, unitId, accessCode}<br/>→ store visitor.id"]
    V --> W["4️⃣ …/visitors/{vid}/disable | enable<br/>…/units/{uid}/vacate<br/>empty-body POSTs"]
```

**Token — password grant only (design decision):**

```
POST https://auth.insomniaccia-qa.com/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}
&username={API_KEY}&password={API_SECRET}
```
```json
{ "token_type": "Bearer", "access_token": "eyJ…", "expires_in": 3600, "refresh_token": "…" }
```

> ⚠ The response includes a `refresh_token`, but **Bear does not use it.** Policy: cache the access token per connection (expiry − 60s) and reuse it for every call. When it expires — or any call returns `401` — acquire a **new token with the password grant again**, retry the failed call once, and only then error out. One grant path, one less long-lived credential held in memory.
>
> Where the four values come from: `client_id`/`client_secret` → the **platform secret**; `username`/`password` (= account `apiKey`/`apiSecret`) → the **account secret**. Both are provisioned and rotated by **DevOps** in Secrets Manager — the admin's API-key entry only *selects* which account secret a property uses.

Every call carries `Authorization: Bearer …`, `api-version: 2.0`, `X-Correlation-ID`. Note: control calls and event calls go to **different hosts**.

**Create visitor** (move-in — the important one):

```json
// POST /facilities/8594/visitors
{ "firstName": "Jane", "lastName": "Smith", "isTenant": true,
  "unitId": 38616, "accessCode": "REDACTED-6-DIGITS" }
```
```json
// response — capture visitor.id IMMEDIATELY; note the code is NOT echoed
{ "visitor": { "id": 71035, "isEnabled": true, "unitId": 38616, "code": null },
  "unit":    { "id": 38616, "status": "Rented" } }
```

**Error rules:** `401` → new password-grant token, retry once · `409` → already in that state, treat as success · other `4xx` → don't retry (data problem, dead-letter for humans) · `5xx`/timeout → backoff retry.

---

## 9. All Flows as Sequence Diagrams

### 9.1 🔑 Token acquisition (password grant only)

```mermaid
sequenceDiagram
    autonumber
    participant AD as OpenTech Adapter
    participant TP as Token Cache (per card)
    participant AUTH as OpenTech Auth API
    participant API as OpenTech Control/Event API

    AD->>TP: GetToken(cardId)
    alt Cached token still valid (now < expiry - 60s)
        TP-->>AD: cached access_token
    else Expired or missing
        TP->>AUTH: POST /auth/token (grant_type=password, key + secret)
        AUTH-->>TP: access_token (refresh_token ignored by design)
        TP-->>AD: token cached until expiry - 60s
    end
    AD->>API: call with Bearer + api-version 2.0 + correlation id
    alt 401 Unauthorized
        AD->>AUTH: POST /auth/token (password grant AGAIN)
        AUTH-->>AD: fresh access_token
        AD->>API: retry the original call once
        API-->>AD: response
    else OK
        API-->>AD: response
    end
```

### 9.2 🧭 Property onboarding (provider chosen + keys entered per property)

```mermaid
sequenceDiagram
    autonumber
    actor SA as Super Admin (Bear staff)
    actor Admin as Org Admin
    participant API as Bear API
    participant SM as AWS Secrets Manager
    participant DB as Bear DB
    participant OT as OpenTech

    Note over SM,DB: 0️⃣ Beforehand — DevOps provisions everything:<br/>platform secret (clientId/clientSecret + URLs) +<br/>account secret (apiKey/apiSecret) + connection row (ARN + fingerprint)
    SA->>OT: 0️⃣ Create the property directly in OpenTech's own portal<br/>(no create-facility API) — propertyNumber = Bear Property.Code

    Note over Admin,OT: 1️⃣ In PROPERTY gate settings — admin enters API KEY only (a selector)
    Admin->>API: provider = OpenTech + apiKey (no secret — protected from admins)
    API->>API: compute key fingerprint
    API->>DB: look up provisioned connection in this org by fingerprint
    alt Match found
        API->>SM: load platform + account secrets
        SM-->>API: credentials (never shown to the admin)
        API->>OT: verify — token → GET /facilities
        OT-->>API: facility list (a stale key fails right here)
        API-->>Admin: ✅ connected + facilities discovered
    else No match
        API-->>Admin: ❌ "no provisioned gate account matches this key —<br/>contact support/DevOps" (nothing created)
    end

    Note over API,DB: 2️⃣ Link facility — FULLY AUTOMATIC (client-confirmed), no admin click
    API->>OT: GET /facilities/detail?propertyNumber={Property.Code}
    alt Exact match (expected — step 0 guarantees it)
        OT-->>API: facility
        API->>DB: gate_facility_mappings (1:1) — linked, no confirmation needed
    else No exact match (fallback only)
        API-->>Admin: manual-resolution screen — pick facility, or wait for Super Admin
    end

    Admin->>API: 3️⃣ Sync units (manual button, unit-level only)
    API->>OT: GET /facilities/{fid}/units
    API->>DB: match by unitNumber → mappings (synced)
    loop Bear units missing vendor-side
        API->>OT: POST /facilities/{fid}/units
        OT-->>API: unit.id
        API->>DB: mapping saved
    end
    loop Units with an ACTIVE Bear credential but no vendor visitor yet
        Note over API,OT: backfill for tenants who moved in before<br/>gate integration existed
        API->>OT: POST /facilities/{fid}/visitors (decrypted code, unitId)
        OT-->>API: visitor.id
        API->>DB: credential → active
    end
    API-->>Admin: 📊 matched / created / needs-review report

    Admin->>API: 4️⃣ Backfill events
    API->>OT: GET events (paged, since beginning)
    API->>DB: INSERT gate_events ON CONFLICT DO NOTHING

    Note over API,OT: 5️⃣ SNS webhook subscription per vendor account (process = V-1)<br/>skipped if the reused connection is already subscribed → property ACTIVE
```

### 9.3 🟢 Move-in

```mermaid
sequenceDiagram
    autonumber
    actor Staff
    participant H as Bear Handler
    participant DB as Bear DB
    participant OT as OpenTech

    Staff->>H: Finalize move-in
    H->>H: generate unique code (CSPRNG + HMAC uniqueness)
    H->>DB: credential (pending_activation) + create_visitor operation + audit
    Note over DB: ✅ committed — intent durable BEFORE vendor call
    H->>OT: POST /facilities/{fid}/visitors (code, unitId, isTenant)
    alt Vendor OK
        OT-->>H: visitor.id
        H->>DB: credential → active (visitor.id stored)
        H-->>Staff: 🎫 code on-screen + confirmation email
    else Vendor slow or down
        H-->>Staff: "code generated — gate activation in progress"
        Note over DB,OT: Worker retries — before any create retry it LISTS<br/>the unit's visitors and adopts an existing match<br/>(no duplicate visitors after a timeout)
    else 400/403 (non-retryable)
        H->>DB: operation → dead, credential → failed
        Note over Staff: 🚨 staff alert + runbook
    end
```

### 9.4 🟠 Delinquency — suspend & reinstate

```mermaid
sequenceDiagram
    autonumber
    actor Src as Staff (Phase 1) / Payment engine (Phase 3)
    participant H as Bear Handler
    participant DB as Bear DB
    participant W as Worker
    participant OT as OpenTech

    Src->>H: SuspendGateAccess (overdue threshold hit)
    H->>DB: credential → suspended, is_gate_restricted = true,<br/>queue suspend_visitor + audit
    Note over DB: tenant portal now WITHHOLDS the code server-side
    W->>OT: POST …/visitors/{vid}/disable (empty body)
    OT-->>W: isEnabled=false, isLockedOut=true
    W->>DB: operation → succeeded

    Src->>H: ReinstateGateAccess (payment received)
    H->>DB: credential → active, is_gate_restricted = false,<br/>queue reinstate_visitor + audit
    W->>OT: POST …/visitors/{vid}/enable (empty body)
    OT-->>W: isEnabled=true
    W->>DB: operation → succeeded
```

### 9.5 🔴 Move-out

```mermaid
sequenceDiagram
    autonumber
    actor Staff
    participant H as Bear Handler
    participant DB as Bear DB
    participant W as Worker
    participant OT as OpenTech

    Staff->>H: Confirm move-out
    H->>DB: ONE transaction — unit status, autopay off,<br/>inspection work order, credential → revoke_pending,<br/>queue vacate_unit (idempotency key revoke:{credId}:{date})
    Note over DB: the "atomic bundle" = all LOCAL effects commit together
    H-->>Staff: ✅ move-out confirmed
    W->>DB: claim operation (SKIP LOCKED)
    W->>OT: POST /facilities/{fid}/units/{uid}/vacate (empty body)
    alt OK or 409 (already vacant)
        OT-->>W: unit → Vacant
        W->>DB: credential → revoked + audit
    else Still failing after 15 min
        Note over W,Staff: 🚨 fail-open alert — tenant may still have gate access,<br/>staff can disable at vendor console while Bear retries
    end
```

### 9.6 🔵 Unit transfer

```mermaid
sequenceDiagram
    autonumber
    actor Staff
    participant H as Bear Handler
    participant DB as Bear DB
    participant W as Worker
    participant OT as OpenTech

    Staff->>H: Transfer tenant U1 → U2 (old-unit move-out date D)
    H->>DB: ONE transaction —<br/>new credential for U2 (new code, pending_activation) + create op<br/>old U1 credential → revoke_scheduled<br/>+ vacate op (status=scheduled, scheduled_for = D in property timezone)
    H->>OT: create visitor on U2 (inline, as move-in)
    OT-->>H: visitor.id → U2 credential active
    H-->>Staff: 🎫 new code for U2 now — old code stays live until D
    Note over DB: date changes → update scheduled_for<br/>transfer cancelled → operation cancelled, U1 back to active
    W->>DB: at D — scheduled → pending, claim
    W->>OT: vacate U1
    OT-->>W: Vacant
    W->>DB: U1 credential → revoked + audit
```

### 9.7 📡 Webhook event ingestion

```mermaid
sequenceDiagram
    autonumber
    participant GWC as Gate Controller
    participant SNS as OpenTech IOE (AWS SNS)
    participant WH as Bear Webhook Endpoint
    participant DB as Bear DB
    participant P as Async Processor (Wolverine + Worker sweep)

    Note over SNS,WH: one-time handshake per subscription
    SNS->>WH: SubscriptionConfirmation
    WH->>WH: verify — webhook_token → SNS cert host allowlist → signature → topic ARN
    WH->>SNS: GET SubscribeURL (confirm)
    WH->>DB: store subscription ARN + audit

    Note over GWC,P: steady state — every keypad interaction
    GWC->>SNS: gateway event
    SNS->>WH: POST Notification (raw text/plain, double-encoded JSON)
    WH->>WH: same 4-step verification, parse, normalize event type
    WH->>DB: INSERT gate_events ON CONFLICT DO NOTHING (pending)
    WH-->>SNS: 200 fast — no vendor calls inline
    WH--)P: local nudge
    P->>DB: resolve credential/unit → last_access_at,<br/>alerts (delinquent denial, invalid-code bursts),<br/>drift detection → processed
    Note over P,DB: nightly poll backfills the same table (same dedup) —<br/>missed webhooks cost latency only, never state
```

### 9.8 🚪 At the keypad (all vendor-side — Bear only *learns* about it)

```mermaid
sequenceDiagram
    autonumber
    actor T as Tenant
    participant K as Keypad
    participant C as Gate Controller
    participant IOE as OpenTech Cloud
    participant B as BearMGMT

    T->>K: Enter PIN
    K->>C: Validate PIN
    C->>C: check visitor (isEnabled, isLockedOut)<br/>+ access profile + time group
    alt Access granted
        C-->>T: gate opens
        C->>IOE: AccessGranted (enum 18)
    else Access denied
        C-->>T: denied (invalid code 15 / wrong area 16 /<br/>delinquent 17 / wrong time 19 / loitering 24)
        C->>IOE: AccessDenied event
    end
    IOE->>B: SNS webhook → gate_events → dashboards + alerts
    Note over C,B: a suspend that hasn't reached the controller yet<br/>will still admit the tenant — event stream is how Bear notices lag
```

---

## 10. Open Points to Clear ⚠

### ✅ Settled by the client (2026-07-18)

- Code length: **4–12 digits, configurable per property** (not per account) — but see **V-10**, a real conflict with the vendor's documented 10-digit max.
- Access profile: **single default for MVP**, no per-tenant selection.
- Facility linking: **fully automatic** on exact `propertyNumber` match, because Bear's Super Admin creates the OpenTech property first with matching numbers.
- Sync: **unit-level only, manual button**, and it now also **pushes access codes** (backfill for tenants who pre-date gate integration).
- **Unit creation is never blocked** by incomplete gate config.
- Gate code section is **hidden entirely** (not restricted-looking) when a property has no gate integration.
- Retry policy: **~5 attempts**, exponential backoff.
- New MVP feature: **failure-notification email per property**.
- Credential model, finalized: admin enters **only the API key** (a selector); DevOps provisions everything else.
- **Different vendors per property** within one org is a confirmed requirement, not just future-proofing.

### Decisions needed from the client (Bear MGMT product)

| # | Question | Recommendation |
|---|---|---|
| C-1 | **Account model** — one OpenTech account per organization, or single Bear-owned (reseller) account? Commercial/liability call; schema supports both | Per-organization |
| C-2 | Gate code **inside the confirmation email** = plaintext credential in a mailbox. Accept, or portal deep-link instead? | Deep-link |
| C-3 | Transfer cut-over time for old-unit revocation (midnight? end of business? gate closing?) — property timezone | End of day, property-local |
| C-4 | **Fail-open SLA** — how long may a failed revocation persist before staff are alerted? | 15 minutes |
| C-5 | Confirm "overlock" (PM-007) = physical padlock **work order**, not a gate API action | As stated |
| C-6 | Gate MVP ships **staff-triggered** (Lease module doesn't exist yet) — acceptable sequencing? | Yes |
| C-7 | ~~Code length~~ **Settled: 4–12 per property.** Still open: may tenants self-regenerate from the portal? | Staff-only regen first |
| C-8 | Delinquency lock scope: per-visitor (recommended) or whole-unit (vendor unit shows Delinquent)? | Per-visitor |

### Questions for the vendor (OpenTech)

| # | Question | Blocks |
|---|---|---|
| V-1 | How is the **SNS webhook subscription** provisioned per account — self-service or support ticket? (Request IOE developer-portal access early, as "Bear MGMT" dev team) | Onboarding automation |
| V-2 | Can `accessCode` be **updated in place**, or is remove + recreate required? | Code regeneration design |
| V-3 | Rate limits per account/host? Safe concurrency for bulk unit sync? | Dispatcher tuning |
| V-4 | Is `/visitors/{vid}/remove` on a **tenant** visitor officially supported? (Worked in QA; spec says vacate the unit) | Move-out fallback path |
| V-5 | Limits on **multiple enabled visitors per unit**? (Co-tenant/spouse codes will be asked for) | Data model headroom |
| V-6 | Webhook **retry policy + ordering guarantees**, authoritative SNS payload field map | Event pipeline hardening |
| V-7 | Is `timeGroupId`/`accessProfileId` = `0` a "use default" sentinel, or must fields be omitted? (POC sent 0) | Request shape |
| V-8 | Idempotency guidance for **create-visitor after a timeout** (no client key exists) | Duplicate-visitor risk |
| V-9 | **Production credential** provisioning + QA credential rotation process | Go-live |
| V-10 | The guide documents `accessCode` as **1–10 digits max**, but the client wants a **4–12 digit** range. Does OpenTech actually reject 11–12 digit codes? | Whether 11–12 digit properties work at all |

### Internal must-dos before production

| Item | Why |
|---|---|
| 🔑 Rotate the QA credentials currently in the POC `appsettings.json`; never copy them into Bear source | They're live vendor secrets |
| 🛠 Define the **DevOps provisioning runbook**: store platform + account secrets in Secrets Manager and register the connection row (ARN + key fingerprint) per organization | Admin key-entry is a lookup — someone must provision first; this process is the prerequisite for every onboarding |
| ⚙️ Deployment/scaling story for `BearMGMT.Worker` | It gains its first production job (the dispatcher) |
| 📨 Lease, Notifications, Payment module contracts (§21 of the full doc) | They trigger/consume the gate commands in Phases 2–3 |

---

*Full detail — schema DDL and triggers, encryption internals, webhook verification code path, portal display matrix, permissions, observability event IDs, failure runbook, testing strategy, phase plan: [gate-access-control-architecture.md](gate-access-control-architecture.md)*
