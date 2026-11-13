"""Definite-length CBOR subset for COSE public keys and attestation objects.

Only unsigned/negative ints, bytes, text, arrays, maps, and bools/null are
supported. Map keys may be ints or strings, as COSE requires.
"""

from __future__ import annotations


class CborError(ValueError):
    pass


def dumps(obj: object) -> bytes:
    return _enc(obj)


def loads(data: bytes) -> object:
    value, rest = _dec(data, 0)
    if rest != len(data):
        raise CborError(f"trailing bytes at offset {rest}")
    return value


def _enc(obj: object) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if isinstance(obj, bool):  # noqa: SIM103 — bool is int subclass
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj >= 0:
            return _uint(0, obj)
        return _uint(1, -1 - obj)
    if isinstance(obj, bytes):
        return _uint(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _uint(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        out = _uint(4, len(obj))
        for item in obj:
            out += _enc(item)
        return out
    if isinstance(obj, dict):
        items = list(obj.items())
        out = _uint(5, len(items))
        for k, v in items:
            out += _enc(k)
            out += _enc(v)
        return out
    raise CborError(f"unsupported type {type(obj)!r}")


def _uint(major: int, n: int) -> bytes:
    if n < 0:
        raise CborError("negative length")
    ai = major << 5
    if n < 24:
        return bytes([ai | n])
    if n < 256:
        return bytes([ai | 24, n])
    if n < 65536:
        return bytes([ai | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([ai | 26]) + n.to_bytes(4, "big")
    if n < 2**64:
        return bytes([ai | 27]) + n.to_bytes(8, "big")
    raise CborError("integer too large")


def _dec(data: bytes, i: int) -> tuple[object, int]:
    if i >= len(data):
        raise CborError("truncated")
    b = data[i]
    major, ai = b >> 5, b & 31
    i += 1
    if major == 7:
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
        raise CborError(f"unsupported simple/float ai={ai}")
    n, i = _len(data, i, ai)
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        if i + n > len(data):
            raise CborError("truncated bytes")
        return data[i : i + n], i + n
    if major == 3:
        if i + n > len(data):
            raise CborError("truncated text")
        return data[i : i + n].decode("utf-8"), i + n
    if major == 4:
        items = []
        for _ in range(n):
            v, i = _dec(data, i)
            items.append(v)
        return items, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = _dec(data, i)
            v, i = _dec(data, i)
            out[k] = v
        return out, i
    raise CborError(f"unsupported major {major}")


def _len(data: bytes, i: int, ai: int) -> tuple[int, int]:
    if ai < 24:
        return ai, i
    if ai == 24:
        if i >= len(data):
            raise CborError("truncated")
        return data[i], i + 1
    if ai == 25:
        if i + 2 > len(data):
            raise CborError("truncated")
        return int.from_bytes(data[i : i + 2], "big"), i + 2
    if ai == 26:
        if i + 4 > len(data):
            raise CborError("truncated")
        return int.from_bytes(data[i : i + 4], "big"), i + 4
    if ai == 27:
        if i + 8 > len(data):
            raise CborError("truncated")
        return int.from_bytes(data[i : i + 8], "big"), i + 8
    raise CborError(f"indefinite or reserved ai={ai}")
