"""Load RP, policy, credential store, and ceremony fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webauthnbind.b64 import b64u_decode
from webauthnbind.cose import CoseError, decode_key
from webauthnbind.parse import ParseError, maybe_b64u, parse_attestation_object, parse_client_data, parse_authenticator_data


class LoadError(ValueError):
    pass


def load_json(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LoadError(f"{path} must contain a JSON object")
    return data


def load_rp(path: str | Path) -> dict[str, Any]:
    rp = load_json(path)
    for key in ("id", "origin", "name"):
        if not isinstance(rp.get(key), str) or not rp[key]:
            raise LoadError(f"rp.{key} must be a non-empty string")
    return rp


def load_policy(path: str | Path) -> dict[str, Any]:
    policy = load_json(path)
    if "user_verification" not in policy:
        policy["user_verification"] = "preferred"
    if "related_origins" not in policy:
        policy["related_origins"] = []
    if "allowed_algs" not in policy:
        policy["allowed_algs"] = ["ES256", "EdDSA"]
    if "allowed_attestation_formats" not in policy:
        policy["allowed_attestation_formats"] = ["none", "packed"]
    if "packed_require_x5c" not in policy:
        policy["packed_require_x5c"] = False
    if "allow_zero_sign_count" not in policy:
        policy["allow_zero_sign_count"] = True
    return policy


def load_store(path: str | Path) -> dict[str, dict[str, Any]]:
    raw = load_json(path)
    creds = raw.get("credentials")
    if not isinstance(creds, list):
        raise LoadError("store.credentials must be a list")
    out: dict[str, dict[str, Any]] = {}
    for i, item in enumerate(creds):
        if not isinstance(item, dict):
            raise LoadError(f"store credential #{i} must be an object")
        try:
            cid = item["id"]
            if not isinstance(cid, str):
                raise LoadError("credential id must be base64url")
            rec = {
                "id": cid,
                "id_raw": b64u_decode(cid),
                "user_handle": item.get("user_handle"),
                "user_handle_raw": b64u_decode(item["user_handle"]) if item.get("user_handle") else None,
                "sign_count": int(item.get("sign_count", 0)),
                "public_key_cose": b64u_decode(item["public_key_cose"]),
                "backup_eligible": bool(item.get("backup_eligible", False)),
                "backup_state": bool(item.get("backup_state", False)),
                "rp_id": item.get("rp_id"),
                "aaguid": item.get("aaguid"),
                "alg": item.get("alg"),
            }
            rec["public_key"] = decode_key(rec["public_key_cose"])
        except (KeyError, ValueError, CoseError) as exc:
            raise LoadError(f"store credential #{i}: {exc}") from exc
        if cid in out:
            raise LoadError(f"duplicate credential id {cid}")
        out[cid] = rec
    return out


def load_ceremony(path: str | Path) -> dict[str, Any]:
    raw = load_json(path)
    typ = raw.get("type")
    if typ not in {"get", "create"}:
        raise LoadError("ceremony type must be get or create")
    try:
        client_raw = maybe_b64u("client_data_json", raw["client_data_json"])
        client = parse_client_data(client_raw)
        expected_challenge = raw.get("expected_challenge")
        if not isinstance(expected_challenge, str):
            raise LoadError("expected_challenge must be a base64url string")
        rec: dict[str, Any] = {
            "type": typ,
            "expected_challenge": expected_challenge,
            "client": client,
            "raw": raw,
        }
        if typ == "get":
            rec["credential_id"] = raw["credential_id"]
            rec["authenticator"] = parse_authenticator_data(maybe_b64u("authenticator_data", raw["authenticator_data"]))
            rec["signature"] = maybe_b64u("signature", raw["signature"])
            rec["user_handle"] = raw.get("user_handle")
        else:
            att = raw.get("attestation_object")
            if att is None:
                raise LoadError("create ceremony needs attestation_object")
            rec["attestation"] = parse_attestation_object(maybe_b64u("attestation_object", att))
            rec["credential_id"] = raw.get("credential_id")
        return rec
    except (KeyError, ParseError, LoadError) as exc:
        raise LoadError(f"ceremony {path}: {exc}") from exc
