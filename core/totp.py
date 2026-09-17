import base64
import hashlib
import hmac
import struct


ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_totp(entry, timestamp):
    secret = entry.secret
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    counter = int(timestamp // entry.period)
    digest = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[entry.algorithm]).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(value % (10**entry.digits)).zfill(entry.digits)
    remaining = entry.period - (int(timestamp) % entry.period)
    return code, remaining
