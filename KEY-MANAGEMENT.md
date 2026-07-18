# PHI Key Management

How the Fernet key that encrypts PHI at rest is protected, and the plan to move
it from a static env value to a **KMS-backed, envelope-encrypted** key using
self-hosted **HashiCorp Vault**.

## Today (baseline)

- A single Fernet key (`PHI_ENCRYPTION_KEY`) lives in
  `/home/hipaa/.hipaa_provision.env` (0600) on the **app host** (`internal-one`).
- It encrypts SSN, contact info, insurance, notes, and TOTP secrets via
  `EncryptedString`.
- **Weakness:** the key sits on the same disk as the database it protects. A
  stolen disk/backup of `internal-one` yields both ciphertext and the key.

## Target architecture — envelope encryption via Vault Transit

```
   app host (internal-one)                 key host (prod-one)
  ┌───────────────────────────┐          ┌──────────────────────────┐
  │ HIPAA API                 │  TLS     │ HashiCorp Vault           │
  │  - holds wrapped DEK       │ ───────► │  transit engine          │
  │  - at boot: Vault unwraps  │  AppRole │   KEK "hipaa-phi"        │
  │    DEK → plaintext in RAM  │ ◄─────── │   (never leaves Vault)   │
  │  - Fernet(DEK) encrypts PHI│  DEK     │  audit device (log)      │
  └───────────────────────────┘          └──────────────────────────┘
```

- **DEK (Data Encryption Key):** the Fernet key that actually encrypts PHI.
  Stored **wrapped** (ciphertext) in the app's config — useless on its own.
- **KEK (Key Encryption Key):** lives inside Vault's `transit` engine and
  **never leaves it**. Vault only wraps/unwraps the DEK on request.
- At **startup** the app authenticates to Vault (AppRole), calls
  `transit/decrypt/hipaa-phi` to unwrap the DEK, and holds the plaintext DEK in
  memory only. All PHI crypto stays local and fast — Vault is touched ~once per
  process start, not per row.

**What this buys us:** stealing the app host's disk/backup no longer decrypts
PHI — an attacker also needs live, authenticated, **audited, revocable** access
to Vault on a different host. Key use is centrally logged; access can be cut off
instantly; rotation is a Vault operation.

**Honest limits of free Vault (OSS):** the KEK is protected by Vault's
**software** barrier, not a hardware HSM. That's a large step up from a plaintext
env file (central audit, rotation, revocation, host separation) but it is *not*
the hardware root-of-trust that AWS KMS / Vault Enterprise+HSM provide. And the
plaintext DEK still lives in the app's RAM while running, so this defends against
disk/backup theft, not a live memory compromise.

## The operational catch: seal / unseal

Vault starts **sealed** and cannot serve keys until unsealed. This directly
affects the app: if `prod-one` reboots, the HIPAA API on `internal-one` **cannot
decrypt PHI until Vault is unsealed**. Options:

| Unseal method | Security | On reboot | Cost |
|---|---|---|---|
| **Shamir keys (manual)** | Highest — unseal keys held by humans, split M-of-N | An operator must unseal Vault before PHI is accessible | Free |
| **Auto-unseal via cloud KMS** | High | Automatic | Reintroduces a small cloud KMS dependency (~$1/mo) — the thing we were avoiding |
| **Auto-unseal via a second Vault (transit)** | High | Automatic | Free, but needs another Vault to bootstrap |

This is the main decision to make. For a system that must not be down after an
unattended reboot, manual Shamir unseal is an availability risk (§164.308(a)(7));
auto-unseal via a cheap cloud KMS is the pragmatic middle ground even in an
otherwise-self-hosted setup.

## Vault setup (prod-one)

1. Install Vault OSS; run as a dedicated `vault` user under systemd.
2. **TLS** on the listener (the app connects from another host — no plaintext).
3. Storage: integrated raft (single node) or file backend, on an encrypted volume.
4. Initialize → capture unseal key shares + root token **offline**; unseal.
5. Enable the **transit** engine; create key `hipaa-phi` (rotation enabled).
6. Policy granting only `transit/encrypt/hipaa-phi` + `transit/decrypt/hipaa-phi`.
7. **AppRole** auth for the app: role bound to that policy; deliver `role_id` +
   a short-lived `secret_id` to `internal-one`.
8. Enable an **audit device** (file) so every key use is logged.
9. Firewall: allow `internal-one` → `prod-one:8200` only.

## App integration (contained change)

Everything already funnels through `security._fernet` (built from
`settings.fernet_key`). Introduce a **key-provider seam**:

- `KEY_PROVIDER=env` (today) → read the raw key from env.
- `KEY_PROVIDER=vault` → on boot, AppRole-login to Vault, unwrap the stored
  wrapped DEK via transit, build Fernet from it.

`EncryptedString`, the models, and all routes are untouched. Add a
`WRAPPED_PHI_DEK` config value (the ciphertext) plus Vault connection settings.

**Timing note:** the database is currently **empty (0 patients)**, so switching
key management now requires **zero PHI re-encryption**. This is the ideal moment
to do it — before any real data lands.

## Rotation

- **KEK rotation (Vault):** `vault write -f transit/keys/hipaa-phi/rotate` — new
  key version; re-wrap the DEK. No data re-encryption. Cheap and frequent.
- **DEK rotation (the data key):** use Fernet **`MultiFernet`** — new DEK encrypts,
  old DEKs still decrypt; a background `rotate-dek` sweep re-saves every row under
  the new DEK; then retire the old. Needed only if the DEK itself is suspected
  compromised.

## Failure modes to design for

- **Vault down/sealed:** app cannot decrypt PHI → it should fail health checks
  loudly, not serve `<decryption-error>`. Boot should fail fast if the DEK can't
  be unwrapped.
- **secret_id expiry:** AppRole `secret_id`s are short-lived; needs a renewal/
  delivery mechanism (e.g., a bootstrap token or response-wrapping).
- **Backups:** the wrapped DEK is safe to back up; the Vault unseal keys/root
  token must be backed up **separately and offline** — losing them loses the KEK
  and therefore all PHI.

## Alternative: AWS KMS (documented, not chosen)

Same envelope pattern, but the KEK lives in AWS KMS (HSM-backed, managed
rotation, provider BAA). ~$1/month; requests within free tier. Chosen against
here to avoid cloud dependency/cost, at the price of a hardware root of trust and
managed unseal. Revisit if a hardware-backed KEK or a provider BAA is required.

## Org prerequisites (unchanged)

Self-hosting the key store means **you** own its security posture — hardening,
patching, backups of unseal material, and physical/host protection of `prod-one`.
A BAA must cover whatever host holds the KEK. See `COMPLIANCE.md`.
