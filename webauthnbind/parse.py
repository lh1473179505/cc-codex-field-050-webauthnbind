"""Parse clientDataJSON, authenticatorData, and attestation objects."""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

from webauthnbind.b64 import b64u_decode
from webauthnbind.cbor import CborError, _dec

FLAG_UP = 1 << 0
FLAG_UV = 1 << 2
FLAG_BE = 1 << 3
FLAG_BS = 1 << 4
FLAG_AT = 1 << 6
FLAG_ED = 1 << 7


class ParseError(ValueError):
    pass


def parse_client_data(raw: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParseError(f"clientDataJSON is not UTF-8 JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ParseError("clientDataJSON must be a JSON object")
    typ = obj.get("type")
    challenge = obj.get("challenge")
    origin = obj.get("origin")
    if not isinstance(typ, str) or not isinstance(challenge, str) or not isinstance(origin, str):
        raise ParseError("clientDataJSON needs string type, challenge, and origin")
    out: dict[str, Any] = {
        "type": typ,
        "challenge": challenge,
        "origin": origin,
        "cross_origin": bool(obj.get("crossOrigin", False)),
        "hash": hashlib.sha256(raw).digest(),
        "raw": raw,
    }
    if "tokenBinding" in obj:
        out["token_binding"] = obj["tokenBinding"]
    return out


def parse_authenticator_data(raw: bytes) -> dict[str, Any]:
    if len(raw) < 37:
        raise ParseError(f"authenticatorData too short ({len(raw)} bytes)")
    rp_id_hash = raw[:32]
    flags = raw[32]
    sign_count = struct.unpack(">I", raw[33:37])[0]
    i = 37
    attested = None
    if flags & FLAG_AT:
        if i + 18 > len(raw):
            raise ParseError("attested credential data truncated")
        aaguid = raw[i : i + 16]
        i += 16
        cred_len = struct.unpack(">H", raw[i : i + 2])[0]
        i += 2
        if i + cred_len > len(raw):
            raise ParseError("credential id truncated")
        cred_id = raw[i : i + cred_len]
        i += cred_len
        try:
            key, j = _dec(raw, i)
        except CborError as exc:
            raise ParseError(f"credential public key: {exc}") from exc
        if not isinstance(key, dict):
            raise ParseError("credential public key must be a COSE map")
        attested = {
            "aaguid": aaguid,
            "credential_id": cred_id,
            "public_key": key,
            "public_key_raw": raw[i:j],
        }
        i = j
    extensions = None
    if flags & FLAG_ED:
        try:
            extensions, j = _dec(raw, i)
        except CborError as exc:
            raise ParseError(f"extensions: {exc}") from exc
        if j != len(raw):
            raise ParseError("trailing bytes after extensions")
    elif i != len(raw):
        raise ParseError("trailing bytes in authenticatorData without ED")
    return {
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "flag_up": bool(flags & FLAG_UP),
        "flag_uv": bool(flags & FLAG_UV),
        "flag_be": bool(flags & FLAG_BE),
        "flag_bs": bool(flags & FLAG_BS),
        "flag_at": bool(flags & FLAG_AT),
        "flag_ed": bool(flags & FLAG_ED),
        "sign_count": sign_count,
        "attested": attested,
        "extensions": extensions,
        "raw": raw,
    }


def parse_attestation_object(raw: bytes) -> dict[str, Any]:
    try:
        obj, j = _dec(raw, 0)
    except CborError as exc:
        raise ParseError(f"attestationObject: {exc}") from exc
    if j != len(raw):
        raise ParseError("trailing bytes after attestationObject")
    if not isinstance(obj, dict):
        raise ParseError("attestationObject must be a map")
    fmt = obj.get("fmt")
    att_stmt = obj.get("attStmt")
    auth = obj.get("authData")
    if not isinstance(fmt, str) or not isinstance(auth, (bytes, bytearray)):
        raise ParseError("attestationObject needs fmt and authData")
    parsed = parse_authenticator_data(bytes(auth))
    return {"fmt": fmt, "att_stmt": att_stmt, "auth_data": parsed, "raw": raw}


def maybe_b64u(field: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    try:
        return b64u_decode(value)
    except Exception as exc:  # noqa: BLE001
        raise ParseError(f"invalid base64url for {field}: {exc}") from exc
