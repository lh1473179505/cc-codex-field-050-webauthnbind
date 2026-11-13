# Report schema

```json
{
  "decision": "allow",
  "reason_codes": [],
  "notes": [],
  "credential_id": "base64url",
  "sign_count_stored": 4,
  "sign_count_asserted": 7,
  "alg": "ES256"
}
```

`decision` is `allow` or `deny`. `reason_codes` uses the names and order in `docs/verify-rules.md`.
