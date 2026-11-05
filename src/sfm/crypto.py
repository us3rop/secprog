"""Versioned AES-GCM envelopes; authenticate before returning plaintext."""
import base64
import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Random import get_random_bytes

MAX_VAULT = 32 * 1024 * 1024
AUTH_ERROR = "wrong password or corrupted vault"


class VaultError(Exception):
    """An error safe to show without exposing secrets."""


def encode(value):
    return base64.b64encode(value).decode("ascii")


def decode(value, length=None):
    raw = base64.b64decode(value, validate=True)
    if length is not None and len(raw) != length:
        raise ValueError("invalid length")
    return raw


def pack(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal(key, plaintext, aad):
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12), mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": encode(cipher.nonce), "data": encode(ciphertext), "tag": encode(tag)}


def unseal(key, envelope, aad):
    cipher = AES.new(key, AES.MODE_GCM, nonce=decode(envelope["nonce"], 12), mac_len=16)
    cipher.update(aad)
    return cipher.decrypt_and_verify(decode(envelope["data"]), decode(envelope["tag"], 16))


def derive(password, salt):
    return scrypt(password.encode("utf-8"), salt, 32, N=2**17, r=8, p=1)


def encrypt(password, master, entries):
    salt = get_random_bytes(16)
    header = {"version": 1, "kdf": "scrypt", "N": 2**17, "r": 8, "p": 1,
              "salt": encode(salt)}
    aad = pack(header)
    # Each save derives a fresh payload key, independently of the wrapping key.
    data_key = HKDF(bytes(master), 32, salt, SHA256, context=b"sfm-payload-v1")
    envelope = {"header": header,
                "wrapped_key": seal(derive(password, salt), bytes(master), aad),
                "payload": seal(data_key, pack(entries), aad)}
    result = pack(envelope)
    if len(result) > MAX_VAULT:
        raise VaultError("vault size limit exceeded (32 MiB)")
    return result


def decrypt(password, raw):
    try:
        envelope = json.loads(raw)
        header = envelope["header"]
        salt = decode(header["salt"], 16)
        # Reject attacker-controlled KDF costs before deriving any key.
        expected = {"version": 1, "kdf": "scrypt", "N": 2**17, "r": 8, "p": 1,
                    "salt": encode(salt)}
        if header != expected:
            raise ValueError("unsupported header")
        aad = pack(header)
        master = unseal(derive(password, salt), envelope["wrapped_key"], aad)
        if len(master) != 32:
            raise ValueError("invalid key")
        data_key = HKDF(master, 32, salt, SHA256, context=b"sfm-payload-v1")
        entries = json.loads(unseal(data_key, envelope["payload"], aad))
        return bytearray(master), entries
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise VaultError(AUTH_ERROR) from None
