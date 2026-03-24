"""Pure Python ECDSA verification on sect233r1 (binary field curve).

Implements GF(2^233) field arithmetic, elliptic curve point operations,
and ECDSA-SHA256 verification for Nintendo 3DS OTP certificate checking.

Zero external dependencies — uses only Python stdlib.

Curve: sect233r1 (NIST B-233, SEC 2 v2)
Field: GF(2^233) with irreducible polynomial t^233 + t^74 + 1
Equation: y^2 + xy = x^3 + x^2 + b
"""
from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# sect233r1 curve parameters (SEC 2 v2)
# ---------------------------------------------------------------------------

_M = 233
_F = (1 << 233) | (1 << 74) | 1  # irreducible polynomial

_A = 1
_B = 0x0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD

_Gx = 0x00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B
_Gy = 0x01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052

# Subgroup order
_N = 0x01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7
_N_BITLEN = _N.bit_length()  # 233

# Cofactor
_H = 2


# ---------------------------------------------------------------------------
# GF(2^233) field arithmetic
# ---------------------------------------------------------------------------

def _gf_reduce(a: int) -> int:
    """Reduce polynomial a modulo t^233 + t^74 + 1."""
    while a.bit_length() > _M:
        shift = a.bit_length() - 1 - _M
        a ^= _F << shift
    return a


def _gf_add(a: int, b: int) -> int:
    """Add two elements in GF(2^233). Addition = XOR."""
    return a ^ b


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^233)."""
    a = _gf_reduce(a)
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return _gf_reduce(result)


def _gf_sqr(a: int) -> int:
    """Square an element in GF(2^233)."""
    return _gf_mul(a, a)


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^233) using extended Euclidean algorithm."""
    if a == 0:
        raise ZeroDivisionError("inverse of zero in GF(2^m)")
    # Extended GCD for polynomials in GF(2)[x]
    old_r, r = _F, a
    old_s, s = 0, 1
    while r != 0:
        # Polynomial division: old_r = q * r + remainder
        q = 0
        temp = old_r
        dr = r.bit_length() - 1
        while temp != 0 and temp.bit_length() - 1 >= dr:
            shift = temp.bit_length() - 1 - dr
            q ^= 1 << shift
            temp ^= r << shift
        remainder = temp
        # Multiply q * s in GF(2)[x] (no reduction — working in polynomial ring)
        qs = 0
        qt = q
        st = s
        while qt:
            if qt & 1:
                qs ^= st
            st <<= 1
            qt >>= 1
        old_r, r = r, remainder
        old_s, s = s, old_s ^ qs
    # old_r should be 1 (the GCD)
    if old_r != 1:
        raise ValueError("element not invertible")
    return _gf_reduce(old_s)


# ---------------------------------------------------------------------------
# Elliptic curve point operations on sect233r1
# y^2 + xy = x^3 + ax^2 + b (a=1)
# ---------------------------------------------------------------------------

# Point at infinity
_INF = None


def _ec_add(
    p: tuple[int, int] | None,
    q: tuple[int, int] | None,
) -> tuple[int, int] | None:
    """Add two points on the curve."""
    if p is _INF:
        return q
    if q is _INF:
        return p

    x1, y1 = p
    x2, y2 = q

    if x1 == x2:
        if y1 == _gf_add(y2, x2):
            # P + (-P) = O
            return _INF
        if y1 == y2:
            # P == Q, use doubling
            return _ec_double(p)
        return _INF

    # lambda = (y1 + y2) / (x1 + x2)
    lam = _gf_mul(_gf_add(y1, y2), _gf_inv(_gf_add(x1, x2)))
    # x3 = lambda^2 + lambda + x1 + x2 + a
    x3 = _gf_add(_gf_add(_gf_add(_gf_sqr(lam), lam), _gf_add(x1, x2)), _A)
    # y3 = lambda * (x1 + x3) + x3 + y1
    y3 = _gf_add(_gf_add(_gf_mul(lam, _gf_add(x1, x3)), x3), y1)
    return (x3, y3)


def _ec_double(p: tuple[int, int] | None) -> tuple[int, int] | None:
    """Double a point on the curve."""
    if p is _INF:
        return _INF

    x1, y1 = p
    if x1 == 0:
        return _INF

    # lambda = x1 + y1/x1
    lam = _gf_add(x1, _gf_mul(y1, _gf_inv(x1)))
    # x3 = lambda^2 + lambda + a
    x3 = _gf_add(_gf_add(_gf_sqr(lam), lam), _A)
    # y3 = x1^2 + (lambda + 1) * x3
    y3 = _gf_add(_gf_sqr(x1), _gf_mul(_gf_add(lam, 1), x3))
    return (x3, y3)


def _ec_mul(k: int, p: tuple[int, int] | None) -> tuple[int, int] | None:
    """Scalar multiplication k*P using double-and-add."""
    if k == 0 or p is _INF:
        return _INF

    result = _INF
    addend = p
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_double(addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# ECDSA-SHA256 verification
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m (integers, not GF(2^m))."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm for integers."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def ecdsa_verify_sha256(
    message: bytes,
    signature_rs: bytes,
    public_key_xy: bytes,
) -> bool:
    """Verify ECDSA-SHA256 signature on sect233r1.

    Args:
        message: The data that was signed.
        signature_rs: 60 bytes (r || s, each 30 bytes big-endian).
        public_key_xy: 60 bytes (x || y, each 30 bytes big-endian).

    Returns:
        True if the signature is valid.
    """
    if len(signature_rs) != 60:
        return False
    if len(public_key_xy) != 60:
        return False

    # Parse signature
    r = int.from_bytes(signature_rs[:30], "big")
    s = int.from_bytes(signature_rs[30:], "big")

    # Parse public key
    qx = int.from_bytes(public_key_xy[:30], "big")
    qy = int.from_bytes(public_key_xy[30:], "big")
    q_point = (qx, qy)

    # Check r, s in [1, n-1]
    if not (1 <= r < _N and 1 <= s < _N):
        return False

    # Compute hash
    h = hashlib.sha256(message).digest()
    e = int.from_bytes(h, "big")
    # Truncate to bit length of n
    if 256 > _N_BITLEN:
        e >>= 256 - _N_BITLEN

    # Compute w = s^(-1) mod n
    w = _modinv(s, _N)

    # Compute u1 = e*w mod n, u2 = r*w mod n
    u1 = (e * w) % _N
    u2 = (r * w) % _N

    # Compute R = u1*G + u2*Q
    g_point = (_Gx, _Gy)
    r_point = _ec_add(_ec_mul(u1, g_point), _ec_mul(u2, q_point))

    if r_point is _INF:
        return False

    # v = R.x (as integer, already in GF(2^m) which is an integer)
    v = r_point[0] % _N

    return v == r
