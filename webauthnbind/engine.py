"""Ceremony verification per docs/verify-rules.md."""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from webauthnbind.b64 import b64u_encode
from webauthnbind.cose import (
    ALG,
    ALG_EDDSA,
    ALG_ES256,
    X,
    Y,
)

REASON_ORDER = [
    "type_mismatch",
    "challenge_mismatch",
    "origin_mismatch",
    "cross_origin_denied",
    "token_binding_invalid",
    "rpid_mismatch",
    "up_required",
    "uv_required",
    "flag_inconsistent",
    "backup_flag_changed",
    "credential_unknown",
    "credential_already_registered",
    "user_handle_mismatch",
    "sign_count_rollback",
    "alg_denied",
    "sig_invalid",
    "attestation_missing",
    "attestation_denied",
]

ALG_NAMES = {ALG_ES256: "ES256", ALG_EDDSA: "EdDSA"}


def _alg_name(key: dict[int, Any]) -> str | None:
    return ALG_NAMES.get(key.get(ALG))


def _verify_signature(key: dict[int, Any], signature: bytes, payload: bytes) -> bool | None:
    """Return True/False for a known key type, None if the key type is unsupported."""
    alg = key.get(ALG)
    try:
        if alg == ALG_ES256:
            if len(signature) != 64:
                return False
            x = key.get(X)
            y = key.get(Y)
            if not isinstance(x, (bytes, bytearray)) or not isinstance(y, (bytes, bytearray)):
                return False
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der = utils.encode_dss_signature(r, s)
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(bytes(x), "big"),
                int.from_bytes(bytes(y), "big"),
                ec.SECP256R1(),
            )
            pub = numbers.public_key()
            pub.verify(der, payload, ec.ECDSA(hashes.SHA256()))
            return True
        if alg == ALG_EDDSA:
            x = key.get(X)
            if not isinstance(x, (bytes, bytearray)) or len(signature) != 64:
                return False
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(x))
            pub.verify(signature, payload)
            return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False
    return None


def _check_client_data(ceremony: dict[str, Any], rp: dict[str, Any], policy: dict[str, Any], codes: set[str], notes: list[str]) -> None:
    client = ceremony["client"]
    expected_type = "webauthn.get" if ceremony["type"] == "get" else "webauthn.create"
    if client["type"] != expected_type:
        codes.add("type_mismatch")
        notes.append(f"clientDataJSON type is {client['type']!r}, expected {expected_type!r}")
    if client["challenge"] != ceremony["expected_challenge"]:
        codes.add("challenge_mismatch")
        notes.append("challenge does not match expected_challenge")
    origin = client["origin"]
    if origin != rp["origin"]:
        related_ok = bool(policy.get("related_origins_enabled")) and origin in policy.get("related_origins", [])
        if not related_ok:
            codes.add("origin_mismatch")
            notes.append(f"origin {origin!r} is not {rp['origin']!r}")
    if client["cross_origin"] and not policy.get("allow_cross_origin", False):
        codes.add("cross_origin_denied")
        notes.append("crossOrigin is true but policy disallows it")
    token_binding = client.get("token_binding")
    if token_binding is not None:
        status = token_binding.get("status") if isinstance(token_binding, dict) else None
        if status not in ("present", "supported"):
            codes.add("token_binding_invalid")
            notes.append(f"tokenBinding status {status!r} is not acceptable")


def _check_authenticator_data(auth: dict[str, Any], rp: dict[str, Any], policy: dict[str, Any], codes: set[str], notes: list[str]) -> None:
    expected_rp_hash = hashlib.sha256(rp["id"].encode("utf-8")).digest()
    if auth["rp_id_hash"] != expected_rp_hash:
        codes.add("rpid_mismatch")
        notes.append("rpIdHash does not match SHA-256 of rp.id")
    if not auth["flag_up"]:
        codes.add("up_required")
        notes.append("user-present bit is not set")
    if policy.get("user_verification") == "required" and not auth["flag_uv"]:
        codes.add("uv_required")
        notes.append("policy requires user verification but UV is not set")
    if auth["flag_bs"] and not auth["flag_be"]:
        codes.add("flag_inconsistent")
        notes.append("BS is set while BE is clear")


def _verify_get(
    ceremony: dict[str, Any],
    store: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    codes: set[str],
    notes: list[str],
    report: dict[str, Any],
) -> None:
    auth = ceremony["authenticator"]
    cid = ceremony["credential_id"]
    report["credential_id"] = cid
    report["sign_count_asserted"] = auth["sign_count"]
    rec = store.get(cid)
    if rec is None:
        codes.add("credential_unknown")
        notes.append(f"credential {cid} is not in the store")
        return
    report["sign_count_stored"] = rec["sign_count"]

    key = rec["public_key"]
    alg_name = _alg_name(key)
    report["alg"] = alg_name
    if alg_name is None or alg_name not in policy.get("allowed_algs", []):
        codes.add("alg_denied")
        notes.append(f"algorithm {alg_name or key.get(ALG)} is not allowed by policy")

    ceremony_uh = ceremony.get("user_handle")
    if ceremony_uh and rec.get("user_handle") and ceremony_uh != rec["user_handle"]:
        codes.add("user_handle_mismatch")
        notes.append("user_handle does not match the stored credential")

    stored = rec["sign_count"]
    asserted = auth["sign_count"]
    if stored == 0 and asserted == 0:
        if not policy.get("allow_zero_sign_count", False):
            codes.add("sign_count_rollback")
            notes.append("both sign counts are zero and policy disallows it")
    elif asserted <= stored:
        codes.add("sign_count_rollback")
        notes.append(f"asserted signCount {asserted} is not greater than stored {stored}")

    if not rec["backup_eligible"] and auth["flag_be"]:
        codes.add("backup_flag_changed")
        notes.append("assertion sets BE but the stored credential is not backup-eligible")
    if auth["flag_bs"] and not rec["backup_state"] and not rec["backup_eligible"]:
        codes.add("backup_flag_changed")
        notes.append("BS changed to true on a credential that is not backup-eligible")

    payload = auth["raw"] + ceremony["client"]["hash"]
    sig_ok = _verify_signature(key, ceremony["signature"], payload)
    if sig_ok is False:
        codes.add("sig_invalid")
        notes.append("signature does not verify with the stored public key")


def _verify_create(
    ceremony: dict[str, Any],
    store: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    codes: set[str],
    notes: list[str],
    report: dict[str, Any],
) -> None:
    att = ceremony["attestation"]
    auth = att["auth_data"]
    attested = auth["attested"] if auth["flag_at"] else None
    if not auth["flag_at"] or attested is None:
        codes.add("attestation_missing")
        notes.append("AT bit or attested credential data is missing")
        report["credential_id"] = ceremony.get("credential_id")
        return

    new_cid = b64u_encode(attested["credential_id"])
    report["credential_id"] = new_cid
    key = {int(k): v for k, v in attested["public_key"].items()}
    alg_name = _alg_name(key)
    report["alg"] = alg_name

    if new_cid in store:
        codes.add("credential_already_registered")
        notes.append(f"credential {new_cid} is already in the store")

    if alg_name is None or alg_name not in policy.get("allowed_algs", []):
        codes.add("alg_denied")
        notes.append(f"algorithm {alg_name or key.get(ALG)} is not allowed by policy")

    fmt = att["fmt"]
    att_stmt = att["att_stmt"]
    if fmt not in policy.get("allowed_attestation_formats", []):
        codes.add("attestation_denied")
        notes.append(f"attestation format {fmt!r} is not allowed by policy")
    elif fmt == "none":
        if not isinstance(att_stmt, dict) or att_stmt:
            codes.add("attestation_denied")
            notes.append("fmt none requires an empty attStmt")
    elif fmt == "packed":
        if not isinstance(att_stmt, dict):
            codes.add("attestation_denied")
            notes.append("packed attestation needs an attStmt map")
        else:
            stmt_alg = att_stmt.get("alg")
            if stmt_alg != key.get(ALG):
                codes.add("attestation_denied")
                notes.append("attStmt alg does not match the credential public key alg")
            x5c = att_stmt.get("x5c")
            sig = att_stmt.get("sig")
            if not x5c and policy.get("packed_require_x5c", False):
                codes.add("attestation_denied")
                notes.append("policy requires x5c for packed attestation")
            payload = auth["raw"] + ceremony["client"]["hash"]
            if not isinstance(sig, (bytes, bytearray)):
                codes.add("sig_invalid")
                notes.append("packed attStmt has no usable sig")
            elif x5c:
                if not _verify_packed_x5c(x5c, bytes(sig), payload):
                    codes.add("sig_invalid")
                    notes.append("packed attestation signature does not verify with the x5c key")
            else:
                sig_ok = _verify_signature(key, bytes(sig), payload)
                if sig_ok is False:
                    codes.add("sig_invalid")
                    notes.append("packed self-attestation signature does not verify")


def _verify_packed_x5c(x5c: Any, signature: bytes, payload: bytes) -> bool:
    if not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], (bytes, bytearray)):
        return False
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(bytes(x5c[0]))
        pub = cert.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            if len(signature) != 64:
                return False
            der = utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            pub.verify(der, payload, ec.ECDSA(hashes.SHA256()))
            return True
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, payload)
            return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False
    return False


def verify(
    ceremony: dict[str, Any],
    store: dict[str, dict[str, Any]],
    rp: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    codes: set[str] = set()
    notes: list[str] = []
    report: dict[str, Any] = {
        "decision": "deny",
        "reason_codes": [],
        "notes": notes,
        "credential_id": None,
        "sign_count_stored": None,
        "sign_count_asserted": None,
        "alg": None,
    }

    _check_client_data(ceremony, rp, policy, codes, notes)
    if ceremony["type"] == "get":
        auth = ceremony["authenticator"]
    else:
        auth = ceremony["attestation"]["auth_data"]
    _check_authenticator_data(auth, rp, policy, codes, notes)

    if ceremony["type"] == "get":
        _verify_get(ceremony, store, policy, codes, notes, report)
    else:
        _verify_create(ceremony, store, policy, codes, notes, report)

    report["reason_codes"] = [c for c in REASON_ORDER if c in codes]
    report["decision"] = "allow" if not codes else "deny"
    return report
