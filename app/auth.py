from __future__ import annotations

import hashlib
import hmac
import secrets

from . import db, util


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()


def check_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex()
        return hmac.compare_digest(calc, h)
    except (ValueError, TypeError):
        return False


def set_user(username: str, pw: str):
    if len(pw) < 8:
        raise ValueError("Use at least 8 characters.")
    db.run("""INSERT INTO users(username,pw_hash,created_at) VALUES(?,?,?)
              ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash""", (username, hash_pw(pw), util.now()))


def verify(username: str, pw: str) -> bool:
    row = db.one("SELECT pw_hash FROM users WHERE username=?", (username,))
    return bool(row) and check_pw(pw, row["pw_hash"])
