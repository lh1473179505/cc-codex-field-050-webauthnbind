"""CLI. inspect already works; verify is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from webauthnbind.b64 import b64u_encode
from webauthnbind.cose import describe
from webauthnbind.load import LoadError, load_ceremony, load_policy, load_rp, load_store


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webauthnbind")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show a parsed ceremony against the credential store")
    ins.add_argument("--ceremony", required=True)
    ins.add_argument("--store", required=True)
    ins.add_argument("--rp", required=False)
    vrf = sub.add_parser("verify", help="decide whether the ceremony should be accepted")
    vrf.add_argument("--ceremony", required=True)
    vrf.add_argument("--store", required=True)
    vrf.add_argument("--rp", required=True)
    vrf.add_argument("--policy", required=True)
    vrf.add_argument("--report", required=True)
    return p


def _hex(data: bytes) -> str:
    return data.hex()


def inspect_payload(ceremony: dict[str, Any], store: dict[str, dict[str, Any]], rp: dict[str, Any] | None) -> dict[str, Any]:
    client = ceremony["client"]
    out: dict[str, Any] = {
        "type": ceremony["type"],
        "expected_challenge": ceremony["expected_challenge"],
        "client": {
            "type": client["type"],
            "challenge": client["challenge"],
            "origin": client["origin"],
            "cross_origin": client["cross_origin"],
            "hash_sha256": _hex(client["hash"]),
        },
        "rp": rp,
    }
    if ceremony["type"] == "get":
        auth = ceremony["authenticator"]
        cid = ceremony["credential_id"]
        known = store.get(cid)
        out["credential_id"] = cid
        out["user_handle"] = ceremony.get("user_handle")
        out["signature_len"] = len(ceremony["signature"])
        out["authenticator"] = {
            "rp_id_hash": _hex(auth["rp_id_hash"]),
            "flags": auth["flags"],
            "up": auth["flag_up"],
            "uv": auth["flag_uv"],
            "be": auth["flag_be"],
            "bs": auth["flag_bs"],
            "sign_count": auth["sign_count"],
        }
        if known:
            out["stored"] = {
                "sign_count": known["sign_count"],
                "backup_eligible": known["backup_eligible"],
                "alg": known.get("alg"),
                "public_key": describe(known["public_key"]),
                "user_handle": known.get("user_handle"),
                "rp_id": known.get("rp_id"),
            }
        else:
            out["stored"] = None
    else:
        att = ceremony["attestation"]
        auth = att["auth_data"]
        out["attestation"] = {
            "fmt": att["fmt"],
            "att_stmt_keys": sorted(att["att_stmt"].keys()) if isinstance(att["att_stmt"], dict) else None,
        }
        out["authenticator"] = {
            "rp_id_hash": _hex(auth["rp_id_hash"]),
            "flags": auth["flags"],
            "up": auth["flag_up"],
            "uv": auth["flag_uv"],
            "at": auth["flag_at"],
            "sign_count": auth["sign_count"],
        }
        if auth["attested"]:
            cred = auth["attested"]
            out["attested"] = {
                "aaguid": _hex(cred["aaguid"]),
                "credential_id": b64u_encode(cred["credential_id"]),
                "public_key": describe({int(k): v for k, v in cred["public_key"].items()}) if all(isinstance(k, int) for k in cred["public_key"]) else "non-int-labels",
            }
    return out


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ceremony = load_ceremony(args.ceremony)
        store = load_store(args.store)
        rp = load_rp(args.rp) if getattr(args, "rp", None) else None
    except (LoadError, OSError) as exc:
        print(f"failed to load inputs: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps(inspect_payload(ceremony, store, rp), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "verify":
        try:
            policy = load_policy(args.policy)
            if rp is None:
                raise LoadError("rp is required for verify")
        except (LoadError, OSError) as exc:
            print(f"failed to load policy or rp: {exc}", file=sys.stderr)
            return 2
        from webauthnbind.engine import verify
        try:
            report = verify(ceremony, store, rp, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
