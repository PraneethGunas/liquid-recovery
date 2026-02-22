"""
Bech32/Bech32m encoding for SegWit addresses.
Reference implementation from BIP173/BIP350.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3


def _polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp, data, spec):
    const = BECH32M_CONST if spec == "bech32m" else BECH32_CONST
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(hrp, witver, witprog):
    """Encode a segwit address with given HRP, witness version, and program."""
    spec = "bech32" if witver == 0 else "bech32m"
    five_bit = convertbits(witprog, 8, 5)
    if five_bit is None:
        return None
    data = [witver] + five_bit
    checksum = _create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in data + checksum])


def decode(bech):
    """Decode a bech32/bech32m address. Returns (hrp, witver, witprog) or (None,None,None)."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None, None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None, None
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        return None, None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    spec = "bech32" if data[0] == 0 else "bech32m"
    const = BECH32M_CONST if spec == "bech32m" else BECH32_CONST
    if _polymod(_hrp_expand(hrp) + data) != const:
        return None, None, None
    witprog = convertbits(data[1:-6], 5, 8, False)
    if witprog is None or len(witprog) < 2 or len(witprog) > 40:
        return None, None, None
    return hrp, data[0], witprog
