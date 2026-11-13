# Verify rules

Reuse `load_ceremony`, `load_store`, `load_rp`, and `load_policy`. Parsing of `clientDataJSON`, `authenticatorData`, COSE keys, and `attestationObject` is already in `webauthnbind.parse` / `webauthnbind.cose`. This lab does not talk to a real authenticator or the network. Python 3 standard library plus the `cryptography` package are enough. Do not shell out to `openssl`, and do not use Docker.

`inspect` only prints what was parsed. `verify` has to decide allow or deny.

## Inputs

- `--ceremony` is either a `get` assertion or a `create` registration. The exact JSON bytes of `client_data_json` (base64url) are what must be hashed; do not reserialize the object.
- `--store` is the currently registered credentials. For `get`, look up `ceremony.credential_id`. For `create`, a new credential id must not already be in the store (`credential_already_registered`).
- `--rp` has `id`, `origin`, and `name`. `rp.id` is the RP ID used for `rpIdHash`.
- `--policy` fields used by verify are listed below. Unknown policy keys can be ignored.

## clientDataJSON

1. `type` must be `webauthn.get` for a `get` ceremony and `webauthn.create` for a `create` ceremony (`type_mismatch` otherwise).
2. `challenge` must equal `expected_challenge` as the same base64url string, with no added padding on either side (`challenge_mismatch`).
3. `origin` must equal `rp.origin`, or — only when `policy.related_origins_enabled` is true — equal one of `policy.related_origins`. Comparison is exact string match (scheme, host, and port as written). `https://login.example.com` and `https://login.example.com:443` are not the same string here. A mismatch is `origin_mismatch`.
4. If `clientDataJSON.crossOrigin` is true and `policy.allow_cross_origin` is false (default is false), deny `cross_origin_denied`.
5. If `tokenBinding` is present: `status` must be `present` or `supported`. Any other status is `token_binding_invalid`. This lab does not further bind a token-binding id.

## authenticatorData (both get and create)

1. `rpIdHash` must be SHA-256 of the UTF-8 RP ID (`rp.id`). A mismatch is `rpid_mismatch`.
2. The user-present bit (UP, 0x01) must be set (`up_required` if not).
3. If `policy.user_verification` is `required`, the UV bit (0x04) must be set (`uv_required`). If the policy value is `preferred` or `discouraged`, UV is not required, but if UV is set it is still recorded.
4. Backup flags: if BS (0x10) is set, BE (0x08) must also be set (`flag_inconsistent`). For a `get` ceremony, if the stored credential has `backup_eligible` false and the assertion sets BE, deny `backup_flag_changed`. BS may change from false to true only when BE is already stored or asserted as true and the stored credential is backup-eligible.
5. Extensions (ED) may be present; this lab does not require any extension. If ED is set, the CBOR must already have parsed (otherwise loading the ceremony fails with exit 2).

## get (assertion)

1. Unknown `credential_id` is `credential_unknown`. If the credential is unknown, skip the store-dependent checks (user handle, sign count, algorithm, signature, and backup flags against the stored BE bit). Still apply clientData and authenticatorData checks that do not need the store.
2. If the ceremony includes `user_handle` (non-empty string) and the stored credential has a `user_handle`, they must be equal as base64url strings (`user_handle_mismatch`). If the ceremony omits `user_handle` or it is null/empty, do not check this rule.
3. Sign count: let `stored` be the store's `sign_count` and `asserted` the count in authenticatorData.
   - If both are 0 and `policy.allow_zero_sign_count` is true, skip the counter check.
   - If both are 0 and that policy is false, deny `sign_count_rollback`.
   - Otherwise, if `asserted` is less than or equal to `stored`, deny `sign_count_rollback`.
   - A strictly greater asserted count is required for success.
4. Signature: signed data is `authenticatorData || SHA-256(clientDataJSON bytes)`.
   - ES256 (COSE alg -7, kty EC2, crv P-256): the signature field is the raw 64-byte `R || S` (32 + 32, big-endian), not DER. Verify with ECDSA-SHA256. Invalid encoding length or a bad signature is `sig_invalid`.
   - EdDSA (COSE alg -8, kty OKP, crv Ed25519): the signature is the raw 64-byte Ed25519 signature. A bad signature is `sig_invalid`.
5. If the stored (or ceremony) algorithm is not in `policy.allowed_algs` (`ES256`, `EdDSA`), deny `alg_denied`. Use the algorithm from the stored COSE key for `get`.

## create (registration)

1. authenticatorData must have the AT bit and attested credential data (`attestation_missing` otherwise).
2. `fmt` must be one of `policy.allowed_attestation_formats`. Anything else, including a format not in that list, is `attestation_denied`.
3. For `fmt` `none`, `attStmt` must be an empty map. A non-empty statement is `attestation_denied`.
4. For `fmt` `packed`:
   - `alg` in `attStmt` must match the credential public key's COSE alg (`attestation_denied` if not).
   - `sig` is encoded the same way as get signatures (raw R||S for ES256, raw 64 for EdDSA). The signed payload is again `authenticatorData || SHA-256(clientDataJSON)`.
   - If `x5c` is absent, this is self-attestation: verify `sig` with the new credential public key. If verification fails, `sig_invalid`.
   - If `x5c` is present, this lab still treats it as packed attestation over the same payload, but `policy.packed_require_x5c` does not add a path-build in this snapshot — presence of `x5c` is enough to satisfy a require-x5c policy; the signature must still verify with the first certificate's public key if you implement it, otherwise prefer documenting self-attestation fixtures. The public fixtures for packed use self-attestation (no `x5c`). If `policy.packed_require_x5c` is true and `x5c` is absent, deny `attestation_denied`.
5. The new credential id (from attested credential data) must not already exist in the store (`credential_already_registered`).
6. `policy.allowed_algs` applies to the new credential public key (`alg_denied`).

## Report and exit

Write the report JSON to `--report`.

- `decision`: `allow` or `deny`.
- `reason_codes`: unique codes in this stable order, only those that apply: `type_mismatch`, `challenge_mismatch`, `origin_mismatch`, `cross_origin_denied`, `token_binding_invalid`, `rpid_mismatch`, `up_required`, `uv_required`, `flag_inconsistent`, `backup_flag_changed`, `credential_unknown`, `credential_already_registered`, `user_handle_mismatch`, `sign_count_rollback`, `alg_denied`, `sig_invalid`, `attestation_missing`, `attestation_denied`.
- `notes`: a list of short strings (may be empty). Mention the credential id or flag when useful.
- `credential_id`: the relevant id (base64url), or null.
- `sign_count_stored` / `sign_count_asserted`: integers or null.
- `alg`: `ES256`, `EdDSA`, or null.

A ceremony is `allow` only when `reason_codes` is empty. If several rules fail, include every code that applies (do not stop at the first failure), except that an unreadable input is an exit 2 and should not produce a deny report.

Exit status: allow → 0, deny → 1. Failure to read or parse a file, or a missing `decision`, → 2.

## Public fixtures

Default files: `--store fixtures/store.json --rp fixtures/rp.json --policy fixtures/policy.json --ceremony fixtures/ceremonies/NAME.json`.

- `ok-es256.json` — `get`, ES256, should allow.
- `ok-eddsa.json` — `get`, Ed25519, should allow.
- `ok-related-origin.json` — `get` from `https://app.example.com` while `policy.related_origins_enabled` is true; should allow. Use `--policy fixtures/policy-related.json` for this one only.
- `origin-mismatch.json` — deny `origin_mismatch`.
- `rpid-mismatch.json` — deny `rpid_mismatch`.
- `challenge-mismatch.json` — deny `challenge_mismatch`.
- `count-rollback.json` — deny `sign_count_rollback`.
- `uv-required.json` — same assertion as ok-es256 but UV is clear; with the default policy (`user_verification` = `required`) deny `uv_required`.
- `userhandle-mismatch.json` — deny `user_handle_mismatch`.
- `flag-inconsistent.json` — BS set, BE clear; deny `flag_inconsistent`.
- `sig-invalid.json` — deny `sig_invalid`.
- `unknown-cred.json` — deny `credential_unknown`.
- `ok-create-none.json` — `create`, `fmt` none, should allow with the default policy.
- `create-packed-ok.json` — `create`, packed self-attestation, should allow with the default policy.
- `create-none-denied.json` — same as `ok-create-none.json` but use `--policy fixtures/policy-direct.json` (`allowed_attestation_formats` is only `packed`, and `packed_require_x5c` is true) and deny `attestation_denied`.
