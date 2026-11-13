"""COSE_Key helpers for ES256 (EC2/P-256) and EdDSA (OKP/Ed25519)."""

from __future__ import annotations

from typing import Any

from webauthnbind.cbor import dumps, loads

# COSE labels
KTY = 1
ALG = 3
CRV = -1
X = -2
Y = -3

KTY_OKP = 1
KTY_EC2 = 2
ALG_ES256 = -7
ALG_EDDSA = -8
CRV_P256 = 1
CRV_ED25519 = 6


class CoseError(ValueError):
    pass


def encode_key(key: dict[int, Any]) -> bytes:
    # Keep a stable label order used by the fixtures: 1, 3, -1, -2, [-3]
    order = [KTY, ALG, CRV, X, Y]
    ordered = {k: key[k] for k in order if k in key}
    for k, v in key.items():
        if k not in ordered:
            ordered[k] = v
    return dumps(ordered)


def decode_key(data: bytes) -> dict[int, Any]:
    obj = loads(data)
    if not isinstance(obj, dict):
        raise CoseError("COSE key must be a map")
    out: dict[int, Any] = {}
    for k, v in obj.items():
        if not isinstance(k, int):
            raise CoseError("COSE key labels must be integers")
        out[k] = v
    if KTY not in out or ALG not in out:
        raise CoseError("COSE key missing kty or alg")
    return out


def describe(key: dict[int, Any]) -> dict[str, Any]:
    kty = key.get(KTY)
    alg = key.get(ALG)
    crv = key.get(CRV)
    name = {ALG_ES256: "ES256", ALG_EDDSA: "EdDSA"}.get(alg, f"alg:{alg}")
    curve = {CRV_P256: "P-256", CRV_ED25519: "Ed25519"}.get(crv, f"crv:{crv}")
    return {
        "kty": kty,
        "alg": name,
        "crv": curve,
        "x_len": len(key[X]) if isinstance(key.get(X), (bytes, bytearray)) else None,
        "has_y": Y in key,
    }
