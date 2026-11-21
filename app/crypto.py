"""加密模块：envelope 加密（KEK 包 DEK，DEK 加密敏感字段）。

安全约定：
- 主密码、KEK、DEK 明文永不落盘、不写日志；
- 盘上只存 base64(nonce + 密文)，每个加密操作使用独立随机 nonce；
- 密钥错误时 AES-GCM 解密抛 InvalidTag，用于解锁验证失败。
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SALT_LEN = 16  # 盐：16 字节
NONCE_LEN = 12  # GCM nonce：12 字节
DEK_LEN = 32  # DEK：32 字节
KEY_LEN = 32
PBKDF2_ITERATIONS = 600_000  # PBKDF2-SHA256 迭代次数
PASSWORD_CHECK = b"VERSION:1"  # 主密码校验固定串


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_kek(password: str, salt: bytes) -> bytes:
    """由主密码 + 盐派生 KEK（PBKDF2-SHA256，60 万次迭代，32 字节）。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_dek() -> bytes:
    """生成 32 字节随机 DEK。"""
    return os.urandom(DEK_LEN)


def _gcm_encrypt_raw(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM 加密，返回 nonce + 密文（密文含 16 字节认证标签）。"""
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ciphertext


def _gcm_decrypt_raw(key: bytes, blob: bytes) -> bytes:
    """解密 nonce+密文；密钥错误或数据被篡改时抛异常。"""
    if len(blob) < NONCE_LEN + 16:
        raise ValueError("密文格式错误")
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_dek(kek: bytes, dek: bytes) -> str:
    """用 KEK 加密 DEK，返回 base64(nonce+密文)。"""
    return _b64encode(_gcm_encrypt_raw(kek, dek))


def decrypt_dek(kek: bytes, encrypted_b64: str) -> bytes:
    """用 KEK 解密 DEK；KEK 错误抛异常。"""
    return _gcm_decrypt_raw(kek, _b64decode(encrypted_b64))


def make_password_check(kek: bytes) -> str:
    """生成主密码校验值：AES-GCM 加密固定串 VERSION:1。"""
    return _b64encode(_gcm_encrypt_raw(kek, PASSWORD_CHECK))


def verify_password_check(kek: bytes, check_b64: str) -> bool:
    """校验主密码；密钥错误抛异常（由调用方决定如何处理）。"""
    return _gcm_decrypt_raw(kek, _b64decode(check_b64)) == PASSWORD_CHECK


def encrypt_value(dek: bytes, value: str) -> str:
    """加密敏感字段值，返回 base64(nonce+密文)。"""
    return _b64encode(_gcm_encrypt_raw(dek, value.encode("utf-8")))


def decrypt_value(dek: bytes, encrypted_b64: str) -> str:
    """解密敏感字段值；DEK 错误抛异常。"""
    return _gcm_decrypt_raw(dek, _b64decode(encrypted_b64)).decode("utf-8")


def encrypt_bytes(key: bytes, data: bytes) -> bytes:
    """加密任意字节（备份导出用），返回 raw nonce+密文。"""
    return _gcm_encrypt_raw(key, data)


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    """解密任意字节（备份导入用）；密钥错误抛异常。"""
    return _gcm_decrypt_raw(key, blob)


TOKEN_AAD = b"asset-vault/token/v2"


def purpose_key(dek: bytes, purpose: str) -> bytes:
    """Versioned, disjoint domains; the legacy field DEK is unchanged."""
    if purpose not in ('approval', 'token') or len(dek) != DEK_LEN:
        raise ValueError('invalid_crypto_domain')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=f'asset-vault/{purpose}/v2'.encode('ascii')).derive(dek)


def canonical_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def approval_aad(approval_id: int, op_type: str) -> bytes:
    if type(approval_id) is not int or approval_id <= 0 or op_type not in ('create', 'update', 'delete'):
        raise ValueError('invalid_approval_context')
    return canonical_json({'format_version': 2, 'id': approval_id, 'op_type': op_type}).encode('utf-8')


def decode_cipher(text: str, expected_plaintext_length=None) -> bytes:
    try:
        raw = base64.b64decode(text.encode('ascii'), validate=True)
        if base64.b64encode(raw).decode('ascii') != text or len(raw) < NONCE_LEN + 16:
            raise ValueError()
        if expected_plaintext_length is not None and len(raw) != NONCE_LEN + 16 + expected_plaintext_length:
            raise ValueError()
        return raw
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise ValueError('invalid_cipher_encoding') from None


def encrypt_aad(key: bytes, data: bytes, aad: bytes) -> str:
    if len(key) != KEY_LEN or not isinstance(aad, bytes) or not aad:
        raise ValueError('invalid_aead_parameters')
    nonce = os.urandom(NONCE_LEN)
    return _b64encode(nonce + AESGCM(key).encrypt(nonce, data, aad))


def decrypt_aad(key: bytes, text: str, aad: bytes) -> bytes:
    if len(key) != KEY_LEN or not isinstance(aad, bytes) or not aad:
        raise ValueError('invalid_aead_parameters')
    raw = decode_cipher(text)
    return AESGCM(key).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], aad)


def token_digest(token: str) -> str:
    return hashlib.sha256(TOKEN_AAD + b'\x00' + token.encode('utf-8')).hexdigest()
