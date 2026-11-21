"""Spec-001 US2：AVBK0002 备份包、受控发布与保留策略。

安全约定：
- 完整快照只在内存加密/解密，磁盘只有认证加密包；无明文临时文件；
- 每包独立随机 BEK（32 字节）与两个独立随机 nonce；KEK 为解锁会话中的
  主密码派生密钥（导出时密码），恢复时只凭备份文件与该密码重建；
- 错误密码与认证失败统一 invalid_credentials_or_corrupt，不暴露内容；
- 发布前必须磁盘回读解密并与捕获快照逻辑记录完全一致；失败不入有效清单；
- 受管目录/临时文件/发布包仅允许当前用户、SYSTEM、Administrators 访问；
- 字节布局与 AAD 唯一定义见 specs/001-data-protection/contracts/backup-format.md。
"""

import base64
import json
import os
import re
import struct
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import crypto

MAGIC = b"AVBK0002"
HEADER_LIMIT = 16 * 1024            # 完整头 ≤16 KiB
MAX_PACKAGE_BYTES = 70 * 1024 * 1024  # 上传/输出包 ≤70 MiB
WRAP_INFO = b"asset-vault/backup-wrap/v2"
PAYLOAD_INFO = b"asset-vault/backup-payload/v2"
KDF_NAME = "pbkdf2-sha256"
KDF_ITERATIONS = 600_000
KDF_LENGTH = 32
SALT_LENGTH = 16
BEK_LENGTH = 32
WRAPPED_LENGTH = 48                 # BEK 32 字节 + 16 字节 GCM 标签
NONCE_LENGTH = 12
PLACEHOLDER = "A" * 64              # 48 字节密文的标准 base64 恒为 64 字符
PURPOSES = ("auto", "manual", "pre_migrate", "pre_restore", "rollback_preserve")
INT_MAX = 2**63 - 1
TIME_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+08:00")
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HEADER_KEYS = frozenset(("backup_id", "captured_at", "change_seq", "db_schema_version",
                         "format_version", "kdf", "payload", "purpose", "restore_epoch",
                         "vault_id", "wrap"))
MANIFEST_NAME = "backup-status.json"
TEMP_SUFFIX = ".writing"
DEFAULT_KEEP = 30
DEFAULT_BUDGET = 512 * 1024 * 1024


class BackupError(RuntimeError):
    """只含稳定错误码，不含用户字段、路径或底层系统消息。"""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ---------- 规范编码 ----------


def canonical_bytes(value) -> bytes:
    """C(H)：所有层键按 ASCII 字典序、无空白、UTF-8。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _parse_b64(text, length):
    """标准字母表、必需 padding、拒绝空白/URL-safe/非规范变体。"""
    if not isinstance(text, str):
        raise BackupError("invalid_package")
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeError):
        raise BackupError("invalid_package") from None
    if _b64(raw) != text or len(raw) != length:
        raise BackupError("invalid_package")
    return raw


def _plain_int(value):
    """整数禁止 bool/浮点。"""
    if type(value) is not int:
        raise BackupError("invalid_package")
    return value


def _uuid(value):
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        raise BackupError("invalid_package")
    try:
        if str(uuid.UUID(value)) != value or uuid.UUID(value).version != 4:
            raise BackupError("invalid_package")
    except ValueError:
        raise BackupError("invalid_package") from None
    return value


def _timestamp(value):
    if not isinstance(value, str) or not TIME_PATTERN.fullmatch(value):
        raise BackupError("invalid_package")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        raise BackupError("invalid_package") from None
    return value


def _ascii_strings(value, path="header"):
    if isinstance(value, str):
        if not value.isascii():
            raise BackupError("invalid_package")
    elif isinstance(value, dict):
        for key, item in value.items():
            _ascii_strings(item, path + "." + key)
    elif isinstance(value, list):
        for item in value:
            _ascii_strings(item, path)


def now_timestamp() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


# ---------- AAD 与包边界 ----------


def wrap_aad(header_length, header0_bytes) -> bytes:
    return WRAP_INFO + b"\x00" + MAGIC + struct.pack(">I", header_length) + header0_bytes


def payload_aad(header_length, header_bytes) -> bytes:
    return PAYLOAD_INFO + b"\x00" + MAGIC + struct.pack(">I", header_length) + header_bytes


def build_header(*, db_schema_version, vault_id, restore_epoch, change_seq, salt,
                 purpose="auto", captured_at=None, backup_id=None,
                 payload_nonce=None, ciphertext_length=0):
    """完整头结构；wrapped_bek 以 64 字符占位，长度计算与契约一致。"""
    if db_schema_version not in (1, 2):
        raise BackupError("unsupported_package")
    if purpose not in PURPOSES:
        raise BackupError("invalid_package")
    if not isinstance(change_seq, int) or isinstance(change_seq, bool) or not 0 <= change_seq <= INT_MAX:
        raise BackupError("invalid_package")
    raw_salt = _parse_b64(salt, SALT_LENGTH) if isinstance(salt, str) else salt
    if len(raw_salt) != SALT_LENGTH:
        raise BackupError("invalid_package")
    header = {
        "backup_id": backup_id or str(uuid.uuid4()),
        "captured_at": captured_at or now_timestamp(),
        "change_seq": change_seq,
        "db_schema_version": db_schema_version,
        "format_version": 2,
        "kdf": {"name": KDF_NAME, "iterations": KDF_ITERATIONS,
                "length": KDF_LENGTH, "salt": _b64(raw_salt)},
        "payload": {"name": "aes-256-gcm",
                    "nonce": _b64(payload_nonce or os.urandom(NONCE_LENGTH)),
                    "ciphertext_length": ciphertext_length},
        "purpose": purpose,
        "restore_epoch": restore_epoch,
        "vault_id": vault_id,
        "wrap": {"name": "aes-256-gcm", "nonce": _b64(os.urandom(NONCE_LENGTH)),
                 "wrapped_bek": PLACEHOLDER},
    }
    _uuid(header["backup_id"])
    _timestamp(header["captured_at"])
    _uuid(header["vault_id"])
    _uuid(header["restore_epoch"])
    return header


def seal(header, snapshot, *, kek, bek, nonce_wrap=None, nonce_payload=None):
    """按契约两步 AAD 完成包装与负载加密，返回完整包字节。

    header 的 wrapped_bek 必须仍是占位符；本函数不修改传入 header。
    """
    if len(kek) != 32 or len(bek) != 32:
        raise BackupError("invalid_aead_parameters")
    # 惰性导入：app.db → app.operations → app.backup 存在模块级环
    from app.db import MAX_SNAPSHOT_BYTES
    if not isinstance(snapshot, bytes) or not snapshot or len(snapshot) > MAX_SNAPSHOT_BYTES:
        raise BackupError("snapshot_too_large")
    if header["wrap"]["wrapped_bek"] != PLACEHOLDER:
        raise BackupError("invalid_package")
    header = deepcopy(header)
    header["payload"]["ciphertext_length"] = len(snapshot) + 16
    # 原始 nonce 字节用于 AEAD 调用；base64 形式仅进入头
    raw_wrap = nonce_wrap if nonce_wrap is not None else os.urandom(NONCE_LENGTH)
    raw_payload = nonce_payload if nonce_payload is not None else os.urandom(NONCE_LENGTH)
    header["wrap"]["nonce"] = _b64(raw_wrap)
    header["payload"]["nonce"] = _b64(raw_payload)

    # 1. 占位头得到完整最终头长度 L
    length = len(canonical_bytes(header))
    if length > HEADER_LIMIT:
        raise BackupError("invalid_package")
    # 2. H0：删除 wrapped_bek 键（不置 null、不留占位）
    header0 = deepcopy(header)
    del header0["wrap"]["wrapped_bek"]
    header0_bytes = canonical_bytes(header0)
    # 3. KEK 用 wrap.nonce 加密 BEK，标准 base64 替换占位串
    wrapped = AESGCM(kek).encrypt(raw_wrap, bek, wrap_aad(length, header0_bytes))
    if len(wrapped) != WRAPPED_LENGTH:
        raise BackupError("invalid_aead_parameters")
    header["wrap"]["wrapped_bek"] = _b64(wrapped)
    # 4. 重新计算完整头，长度必须仍为 L
    header_bytes = canonical_bytes(header)
    if len(header_bytes) != length:
        raise BackupError("invalid_package")
    ciphertext = AESGCM(bek).encrypt(raw_payload, snapshot,
                                     payload_aad(length, header_bytes))
    return MAGIC + struct.pack(">I", length) + header_bytes + ciphertext, header


def encrypt_package(snapshot, *, kek, salt, vault_id, restore_epoch, change_seq,
                    db_schema_version=2, purpose="auto", captured_at=None,
                    backup_id=None, nonce_wrap=None, nonce_payload=None, bek=None):
    """随机 BEK + 独立 nonce 加密完整快照；返回 (blob, header)。"""
    header = build_header(db_schema_version=db_schema_version, vault_id=vault_id,
                          restore_epoch=restore_epoch, change_seq=change_seq,
                          salt=salt, purpose=purpose, captured_at=captured_at,
                          backup_id=backup_id, payload_nonce=b"\0" * NONCE_LENGTH,
                          ciphertext_length=0)
    return seal(header, snapshot, kek=kek, bek=bek or os.urandom(BEK_LENGTH),
                nonce_wrap=nonce_wrap, nonce_payload=nonce_payload)


# ---------- 解析（先边界/格式，后 KDF） ----------


def parse_package(blob):
    """严格边界与头校验；返回 (header, ciphertext, header_length)。不执行 KDF。"""
    if not isinstance(blob, bytes) or not blob:
        raise BackupError("invalid_package")
    if len(blob) > MAX_PACKAGE_BYTES:
        raise BackupError("package_too_large")
    if not blob.startswith(MAGIC):
        raise BackupError("invalid_package")
    if len(blob) < 12:
        raise BackupError("invalid_package")
    length = struct.unpack(">I", blob[8:12])[0]
    if length > HEADER_LIMIT:
        raise BackupError("invalid_package")
    if len(blob) < 12 + length:
        raise BackupError("invalid_package")
    header_bytes = blob[12:12 + length]
    try:
        header = json.loads(header_bytes.decode("utf-8"),
                            object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, UnicodeError):
        raise BackupError("invalid_package") from None
    if not isinstance(header, dict):
        raise BackupError("invalid_package")
    # 输入头必须逐字节等于 C(解析后的 H)：拒绝重复键/非规范编码/尾随空白
    if canonical_bytes(header) != header_bytes:
        raise BackupError("invalid_package")
    _ascii_strings(header)
    _validate_header(header)
    ciphertext_length = header["payload"]["ciphertext_length"]
    if len(blob) != 12 + length + ciphertext_length:
        raise BackupError("invalid_package")  # 截断/尾随字节
    return header, blob[12 + length:], length


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError("invalid_package")
        result[key] = value
    return result


def _validate_header(header):
    if set(header) != HEADER_KEYS:
        raise BackupError("invalid_package")
    if _plain_int(header["format_version"]) != 2:
        raise BackupError("unsupported_package")
    if _plain_int(header["db_schema_version"]) not in (1, 2):
        raise BackupError("unsupported_package")
    _plain_int(header["change_seq"])
    if not 0 <= header["change_seq"] <= INT_MAX:
        raise BackupError("invalid_package")
    _timestamp(header["captured_at"])
    _uuid(header["backup_id"])
    _uuid(header["vault_id"])
    _uuid(header["restore_epoch"])
    if header["purpose"] not in PURPOSES:
        raise BackupError("invalid_package")
    kdf = header["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != {"name", "iterations", "length", "salt"}:
        raise BackupError("invalid_package")
    # 首版仅接受精确参数集；在执行昂贵 KDF 前拒绝恶意参数
    if kdf["name"] != KDF_NAME or _plain_int(kdf["iterations"]) != KDF_ITERATIONS \
            or _plain_int(kdf["length"]) != KDF_LENGTH:
        raise BackupError("unsupported_package")
    _parse_b64(kdf["salt"], SALT_LENGTH)
    wrap = header["wrap"]
    if not isinstance(wrap, dict) or set(wrap) != {"name", "nonce", "wrapped_bek"}:
        raise BackupError("invalid_package")
    if wrap["name"] != "aes-256-gcm":
        raise BackupError("unsupported_package")
    _parse_b64(wrap["nonce"], NONCE_LENGTH)
    _parse_b64(wrap["wrapped_bek"], WRAPPED_LENGTH)
    payload = header["payload"]
    if not isinstance(payload, dict) or set(payload) != {"name", "nonce", "ciphertext_length"}:
        raise BackupError("invalid_package")
    if payload["name"] != "aes-256-gcm":
        raise BackupError("unsupported_package")
    _parse_b64(payload["nonce"], NONCE_LENGTH)
    cipher_len = _plain_int(payload["ciphertext_length"])
    if cipher_len < 16 or cipher_len > MAX_PACKAGE_BYTES:
        raise BackupError("package_too_large")


def derive_kek(password: str, header) -> bytes:
    """由导出时密码 + 头内盐重建 KEK；参数已在解析时锁定为唯一允许集合。"""
    return crypto.derive_kek(password, _parse_b64(header["kdf"]["salt"], SALT_LENGTH))


def unwrap_snapshot(header, ciphertext, header_length, kek) -> bytes:
    """解包 BEK 并认证完整负载；错误密码与认证失败统一同一错误。"""
    wrapped = _parse_b64(header["wrap"]["wrapped_bek"], WRAPPED_LENGTH)
    header0 = deepcopy(header)
    del header0["wrap"]["wrapped_bek"]
    try:
        bek = AESGCM(kek).decrypt(_parse_b64(header["wrap"]["nonce"], NONCE_LENGTH),
                                  wrapped, wrap_aad(header_length, canonical_bytes(header0)))
    except InvalidTag:
        raise BackupError("invalid_credentials_or_corrupt") from None
    if len(bek) != BEK_LENGTH:
        raise BackupError("invalid_credentials_or_corrupt")
    try:
        snapshot = AESGCM(bek).decrypt(_parse_b64(header["payload"]["nonce"], NONCE_LENGTH),
                                       ciphertext, payload_aad(header_length, canonical_bytes(header)))
    except InvalidTag:
        raise BackupError("invalid_credentials_or_corrupt") from None
    from app.db import MAX_SNAPSHOT_BYTES  # 惰性导入，避免模块级环
    if len(snapshot) > MAX_SNAPSHOT_BYTES:
        raise BackupError("package_too_large")
    return snapshot


def decrypt_package(blob, password):
    """解析→派生 KEK→解包→认证解密；返回 (header, snapshot)。"""
    header, ciphertext, length = parse_package(blob)
    return header, unwrap_snapshot(header, ciphertext, length, derive_kek(password, header))


def open_package(blob, kek):
    """已知 KEK（自动备份回读）的解密入口。"""
    header, ciphertext, length = parse_package(blob)
    return header, unwrap_snapshot(header, ciphertext, length, kek)


# ---------- Windows 受限 ACL（与保全工具同策略：当前用户 + SYSTEM + BA） ----------

_WIN = None


class _Windows:
    def __init__(self):
        if os.name != "nt":
            raise BackupError("permissions_unavailable")
        import ctypes
        from ctypes import wintypes as W
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        P = ctypes.c_void_p
        for name, (args, result) in {
            "OpenProcessToken": ([W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)], W.BOOL),
            "GetTokenInformation": ([W.HANDLE, ctypes.c_int, P, W.DWORD, ctypes.POINTER(W.DWORD)], W.BOOL),
            "ConvertSidToStringSidW": ([P, ctypes.POINTER(P)], W.BOOL),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW": ([W.LPCWSTR, W.DWORD, ctypes.POINTER(P), ctypes.POINTER(W.DWORD)], W.BOOL),
            "ConvertSecurityDescriptorToStringSecurityDescriptorW": ([P, W.DWORD, W.DWORD, ctypes.POINTER(P), ctypes.POINTER(W.DWORD)], W.BOOL),
            "SetFileSecurityW": ([W.LPCWSTR, W.DWORD, P], W.BOOL),
            "GetNamedSecurityInfoW": ([W.LPWSTR, ctypes.c_int, W.DWORD, P, P, P, P, ctypes.POINTER(P)], W.DWORD),
        }.items():
            fn = getattr(self.adv, name)
            fn.argtypes, fn.restype = args, result
        for name, args, result in (
                ("GetCurrentProcess", [], W.HANDLE), ("CloseHandle", [W.HANDLE], W.BOOL),
                ("LocalFree", [P], P)):
            fn = getattr(self.kernel, name)
            fn.argtypes, fn.restype = args, result
        token = W.HANDLE()
        if not self.adv.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise BackupError("backup_permissions_failed")
        try:
            size = W.DWORD()
            self.adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            if not self.adv.GetTokenInformation(token, 1, buf, size.value, ctypes.byref(size)):
                raise BackupError("backup_permissions_failed")
            string = P()
            if not self.adv.ConvertSidToStringSidW(
                    ctypes.cast(buf, ctypes.POINTER(P))[0], ctypes.byref(string)):
                raise BackupError("backup_permissions_failed")
            try:
                self.sid = ctypes.wstring_at(string)
            finally:
                self.kernel.LocalFree(string)
        finally:
            self.kernel.CloseHandle(token)

    def sddl(self, directory):
        flags = "OICI" if directory else ""
        return "D:P" + "".join(f"(A;{flags};FA;;;{sid})" for sid in (self.sid, "SY", "BA"))

    def descriptor(self, path):
        import ctypes
        from ctypes import c_void_p as P
        result = P()
        if not self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                self.sddl(path.is_dir()), 1, ctypes.byref(result), None):
            raise BackupError("backup_permissions_failed")
        return result

    def stringify(self, descriptor):
        import ctypes
        string = ctypes.c_void_p()
        if not self.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, 4, ctypes.byref(string), None):
            raise BackupError("backup_permissions_failed")
        try:
            return ctypes.wstring_at(string)
        finally:
            self.kernel.LocalFree(string)


def _windows():
    global _WIN
    if _WIN is None:
        _WIN = _Windows()
    return _WIN


def protect(path):
    """受保护 DACL：仅当前用户/SYSTEM/Administrators。"""
    path = Path(path)
    win = _windows()
    descriptor = win.descriptor(path)
    try:
        if not win.adv.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor):
            raise BackupError("backup_permissions_failed")
    finally:
        win.kernel.LocalFree(descriptor)


def check_permissions(path):
    """核验实际 DACL 与受保护模板逐字符一致；失败不可发布。"""
    import ctypes
    from ctypes import c_void_p as P
    path = Path(path)
    win = _windows()
    actual, expected = P(), P()
    try:
        expected = win.descriptor(path)
        if win.adv.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(actual)):
            raise BackupError("backup_permissions_failed")
        if win.stringify(actual) != win.stringify(expected):
            raise BackupError("backup_permissions_failed")
        return True
    finally:
        if actual.value:
            win.kernel.LocalFree(actual)
        if expected.value:
            win.kernel.LocalFree(expected)


# ---------- 包存储：发布 / 保留 / 清单 ----------


def ensure_directory(directory):
    """受管目录必须先建立并核验受限 ACL；失败拒绝创建任何文件。"""
    directory = Path(directory)
    if directory.exists():
        if not directory.is_dir():
            raise BackupError("backup_permissions_failed")
        check_permissions(directory)
        return directory
    directory.mkdir(parents=True)
    try:
        protect(directory)
        check_permissions(directory)
    except BackupError:
        directory.rmdir()
        raise
    return directory


def snapshot_identity(snapshot):
    """从快照内存库只读提取包元信息；格式 1/2 均可，缺失身份视为不支持。"""
    from app import db
    with db.deserialize_snapshot(snapshot) as conn:
        meta = db.meta_values(conn)
        version = db.probe_connection(conn).version
    salt = meta.get("salt")
    if not isinstance(salt, str):
        raise BackupError("invalid_package")
    return {"db_schema_version": version, "salt": salt,
            "vault_id": meta.get("vault_id"), "restore_epoch": meta.get("restore_epoch"),
            "change_seq": int(meta["change_seq"]) if version == 2 else 0}


def _package_purpose(path):
    try:
        header, _, _ = parse_package(path.read_bytes())
        return header
    except BackupError:
        return None  # 损坏包不参与保留计算，也不被误删有效材料


class BackupStore:
    """一个受管目录的备份包清单与发布；只处理认证加密包。"""

    def __init__(self, directory, *, keep=DEFAULT_KEEP, budget=DEFAULT_BUDGET):
        self.directory = Path(directory)
        self.keep = keep
        self.budget = budget

    # -- 发布 --

    def publish_verified(self, blob, header, *, kek, expected_records, fault=None):
        """独占加密临时文件→fsync→磁盘回读解密→逻辑匹配→原子发布。

        返回发布文件路径；任何失败清理临时文件，不覆盖既有包。
        """
        fault = fault or (lambda node: None)
        directory = ensure_directory(self.directory)
        final = directory / self.package_name(header)
        temp = directory / (final.name + TEMP_SUFFIX)
        try:
            if final.exists():
                raise BackupError("target_exists")
            with temp.open("xb") as stream:
                protect(temp)
                check_permissions(temp)
                if stream.write(blob) != len(blob):
                    raise BackupError("short_write")
                stream.flush()
                os.fsync(stream.fileno())
            check_permissions(temp)
            fault("written")
            readback = temp.read_bytes()
            if readback != blob:
                raise BackupError("readback_mismatch")
            _, snapshot = open_package(readback, kek)
            if not records_match(snapshot, expected_records):
                raise BackupError("readback_mismatch")
            fault("verified")
            if final.exists():
                raise BackupError("target_exists")
            temp.replace(final)  # 同目录原子改名；目标已存在则失败
            check_permissions(final)
            fault("published")
            return final
        except OSError as exc:
            raise BackupError("backup_write_failed") from exc
        finally:
            if temp.exists():
                temp.unlink()

    @staticmethod
    def package_name(header):
        stamp = header["captured_at"].replace(":", "").replace("-", "")[:15]
        return f"backup-{stamp}-{header['backup_id'][:8]}.avbak"

    def _write_origin_sidecar(self, package_path, header, trigger):
        """在备份包旁写同名前缀 .origin.json 来源标记（data-model 5.1）。

        内容只含非敏感字段 {backup_id, trigger, created_at}，与包同目录、同
        受限 ACL；原子临时文件 + fsync + 回读 + 改名，失败抛 BackupError，
        绝不写半份 sidecar。不进加密包头、不参与 *.avbak 清单。
        """
        sidecar = package_path.with_name(
            package_path.name[: -len(".avbak")] + ".origin.json")
        payload = canonical_bytes({
            "backup_id": header["backup_id"],
            "trigger": trigger,
            "created_at": header["captured_at"],
        })
        temp = sidecar.with_name(sidecar.name + TEMP_SUFFIX)
        try:
            if sidecar.exists():
                raise BackupError("target_exists")
            with temp.open("xb") as stream:
                protect(temp)
                check_permissions(temp)
                if stream.write(payload) != len(payload):
                    raise BackupError("short_write")
                stream.flush()
                os.fsync(stream.fileno())
            check_permissions(temp)
            if temp.read_bytes() != payload:
                raise BackupError("readback_mismatch")
            temp.replace(sidecar)
            check_permissions(sidecar)
        except BackupError:
            raise
        except OSError:
            raise BackupError("backup_write_failed") from None
        finally:
            if temp.exists():
                temp.unlink()

    # -- 完整创建 --

    # sidecar 触发来源白名单：目前仅改密前置保全一种（data-model 5.1）
    SIDECAR_TRIGGERS = frozenset(("password_change",))

    def create(self, snapshot, *, kek, purpose="auto", fault=None,
               expected_records=None, trigger=None):
        """加密→发布→保留→清单；返回结果 dict，不向上抛业务异常。

        trigger 非空时在包旁落同名前缀 .origin.json sidecar（受限 ACL），
        只记录非敏感来源标记；现有只 glob *.avbak 的程序对其完全不可见。
        """
        from app import db
        attempt_at = now_timestamp()
        try:
            identity = snapshot_identity(snapshot)
            if expected_records is None:
                with db.deserialize_snapshot(snapshot) as conn:
                    expected_records = db.logical_records(conn)
            blob, header = encrypt_package(
                snapshot, kek=kek, salt=identity["salt"], vault_id=identity["vault_id"],
                restore_epoch=identity["restore_epoch"], change_seq=identity["change_seq"],
                db_schema_version=identity["db_schema_version"], purpose=purpose)
            if len(blob) > MAX_PACKAGE_BYTES:
                raise BackupError("package_too_large")
            final = self.publish_verified(blob, header, kek=kek,
                                          expected_records=expected_records, fault=fault)
            if trigger is not None:
                if trigger not in self.SIDECAR_TRIGGERS:
                    raise BackupError("invalid_package")
                self._write_origin_sidecar(final, header, trigger)
            self._prune(header)
            manifest = self._read_manifest() or {}
            if manifest.get("vault_id") != identity["vault_id"] or \
                    manifest.get("restore_epoch") != identity["restore_epoch"]:
                manifest = {"vault_id": identity["vault_id"],
                            "restore_epoch": identity["restore_epoch"],
                            "latest_verified_seq": 0}
            manifest.update({
                "latest_saved_seq": max(int(manifest.get("latest_saved_seq", 0)),
                                        identity["change_seq"]),
                "latest_verified_seq": max(int(manifest.get("latest_verified_seq", 0)),
                                           identity["change_seq"]),
                "last_attempt_at": attempt_at, "last_success_at": attempt_at,
                "status": "ok", "error_code": None, "retry_available": False,
                "local_only": True})
            self._write_manifest(manifest)
            return {"status": "ok", "backup_id": header["backup_id"],
                    "change_seq": identity["change_seq"], "error_code": None,
                    "retry_available": False}
        except BackupError as exc:
            self._mark_failed(identity, attempt_at, exc.code)
            return {"status": "failed", "backup_id": None, "error_code": exc.code,
                    "retry_available": True}
        except Exception:
            self._mark_failed(identity, attempt_at, "backup_failed")
            return {"status": "failed", "backup_id": None, "error_code": "backup_failed",
                    "retry_available": True}

    def _mark_failed(self, identity, attempt_at, code):
        """数据已保存、备份失败：记录已尝试序号，保留上一有效包。"""
        try:
            if not identity.get("vault_id"):
                return
            manifest = self._read_manifest() or {}
            if manifest.get("vault_id") != identity["vault_id"] or \
                    manifest.get("restore_epoch") != identity["restore_epoch"]:
                manifest = {"vault_id": identity["vault_id"],
                            "restore_epoch": identity["restore_epoch"],
                            "latest_verified_seq": 0}
            manifest.update({
                "latest_saved_seq": max(int(manifest.get("latest_saved_seq", 0)),
                                        identity.get("change_seq") or 0),
                "last_attempt_at": attempt_at, "status": "failed",
                "error_code": code, "retry_available": True, "local_only": True})
            self._write_manifest(manifest)
        except Exception:
            pass  # 清单失败不得掩盖原始备份失败码

    # -- 保留策略 --

    def _prune(self, current_header):
        """先验证新包后才清理；仅当前身份的 auto 包，最后有效包不删。"""
        try:
            entries = []
            for path in self.directory.glob("*.avbak"):
                header = _package_purpose(path)
                if header is None or header["purpose"] != "auto":
                    continue  # 手动/迁移前/覆盖前材料不自动清理
                if header["vault_id"] != current_header["vault_id"] or \
                        header["restore_epoch"] != current_header["restore_epoch"]:
                    continue  # 旧代次包保留为历史恢复材料
                entries.append((header["change_seq"], path))
            entries.sort()
            excess = len(entries) - self.keep
            total = sum(path.stat().st_size for _, path in entries)
            removed = False
            for seq, path in entries:
                if len(entries) <= 1:
                    break  # 最后一份有效包不删
                if excess > 0:
                    entries.remove((seq, path))
                    path.unlink()
                    excess -= 1
                    removed = True
                    continue
                if total <= self.budget:
                    break
                total -= path.stat().st_size
                entries.remove((seq, path))
                path.unlink()
                removed = True
            return removed
        except OSError:
            return False  # 无法安全清理时保留超限并提示，不破坏数据

    # -- 清单 --

    def _manifest_path(self):
        return self.directory / MANIFEST_NAME

    def _read_manifest(self):
        path = self._manifest_path()
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (ValueError, OSError):
            return None

    def _write_manifest(self, manifest):
        path = self._manifest_path()
        temp = path.with_suffix(".json" + TEMP_SUFFIX)
        blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            with temp.open("wb") as stream:
                written = stream.write(blob)
                if written != len(blob):  # 短写（空间不足/写入中断）不得静默继续
                    raise OSError("manifest_short_write")
                stream.flush()
                os.fsync(stream.fileno())
            if temp.read_bytes() != blob:  # 改名前磁盘回读，保住上一份好清单
                raise OSError("manifest_readback_mismatch")
            os.replace(temp, path)
        except OSError:
            # fsync/短写/改名失败时不得遗留半成品临时文件，也不覆盖旧清单
            try:
                temp.unlink()
            except OSError:
                pass
            raise

    def manifest(self):
        return self._read_manifest()

    def list_packages(self, vault_id, restore_epoch, *, limit=30):
        """列出受管目录内备份包的非敏感清单（只解析未加密头部，不需密码）。

        自动包按保留策略留最近 30 份；手动导出、恢复前保护、迁移前保护、
        回退保全包同样列出。current_epoch=False 表示属于旧代次（改主密码或
        恢复之前的包），打开它需要当时的主密码。
        """
        items = []
        try:
            paths = sorted(self.directory.glob("*.avbak"))
        except OSError:
            return []
        for path in paths:
            header = _package_purpose(path)
            if header is None:
                continue  # 损坏/无法识别的包不进清单，也不影响其余包展示
            try:
                size = path.stat().st_size
            except OSError:
                continue
            try:
                seq = int(header.get("change_seq") or 0)
            except (TypeError, ValueError):
                seq = 0
            items.append({
                "change_seq": seq,
                "captured_at": header.get("captured_at"),
                "backup_id": str(header.get("backup_id", ""))[:8],
                "purpose": header.get("purpose", "auto"),
                "current_epoch": header.get("vault_id") == vault_id
                                 and header.get("restore_epoch") == restore_epoch,
                "size": size,
            })
        items.sort(key=lambda x: (x["change_seq"], x["captured_at"] or ""), reverse=True)
        return items[:max(1, min(int(limit), 100))]

    def locate_package(self, backup_id):
        """按 backup_id 前 8 位在受管目录内定位已认证包文件（拒绝任意路径输入）。"""
        key = str(backup_id)[:8].lower()
        if not re.fullmatch(r"[0-9a-f]{8}", key):
            return None
        try:
            paths = list(self.directory.glob("*.avbak"))
        except OSError:
            return None
        for path in paths:
            header = _package_purpose(path)
            if header is None:
                continue
            if str(header.get("backup_id", ""))[:8] == key:
                return path, header
        return None

    def status_for(self, vault_id, restore_epoch, change_seq, *, kek=None, dek=None):
        """按三元组精确比较；清单丢失时只从匹配身份的已认证包重建。"""
        status = {"vault_id": vault_id, "restore_epoch": restore_epoch,
                  "latest_saved_seq": 0, "latest_verified_seq": 0,
                  "status": "pending", "error_code": None, "retry_available": True,
                  "local_only": True, "last_attempt_at": None, "last_success_at": None}
        manifest = self._read_manifest()
        if manifest and manifest.get("vault_id") == vault_id and \
                manifest.get("restore_epoch") == restore_epoch:
            status.update({key: manifest[key] for key in
                           ("latest_saved_seq", "latest_verified_seq", "status",
                            "last_attempt_at", "last_success_at", "local_only")
                           if key in manifest})
            status["error_code"] = manifest.get("error_code")
            status["retry_available"] = bool(manifest.get("retry_available"))
        else:
            # 清单丢失/身份不符：文件存在不等于已验证，须包回读认证
            verified = self._rebuild_verified(vault_id, restore_epoch, kek, dek)
            status["latest_saved_seq"] = verified
            status["latest_verified_seq"] = verified
            status["status"] = "ok" if verified == change_seq else "pending"
            status["retry_available"] = verified != change_seq
        if status["latest_verified_seq"] == change_seq:
            status["status"] = "ok"
            status["retry_available"] = False
        elif status["latest_saved_seq"] >= change_seq:
            status["status"] = "pending" if status["status"] != "failed" else "failed"
        else:
            status["status"] = "pending"
            status["retry_available"] = True
        return status

    def _rebuild_verified(self, vault_id, restore_epoch, kek=None, dek=None):
        """只信任能被 KEK 解开并匹配三元组的新包；kek/dek 缺失时返回 0。"""
        from app import db
        if kek is None or dek is None:
            return 0
        best = 0
        try:
            for path in self.directory.glob("*.avbak"):
                try:
                    header, _, _ = parse_package(path.read_bytes())
                except (BackupError, OSError):
                    continue
                if header["vault_id"] != vault_id or header["restore_epoch"] != restore_epoch:
                    continue
                if header["change_seq"] <= best:
                    continue
                try:
                    _, snapshot = open_package(path.read_bytes(), kek)
                    with db.deserialize_snapshot(snapshot) as conn:
                        db.validate_records(conn, kek, dek)
                except Exception:
                    continue  # 无法认证的包不算已验证
                best = header["change_seq"]
            return best
        except OSError:
            return best

    def cleanup_temps(self):
        """清除历史中断遗留的加密临时文件（仅限本受管目录）。"""
        removed = 0
        try:
            for temp in self.directory.glob("*" + TEMP_SUFFIX):
                try:
                    temp.unlink()
                    removed += 1
                except OSError:
                    pass
        except OSError:
            pass
        return removed


def records_match(snapshot, expected_records) -> bool:
    """只输出布尔结论：完整 meta/记录/序号一致；不输出差异内容。"""
    from app import db
    try:
        with db.deserialize_snapshot(snapshot) as conn:
            return db.logical_records(conn) == expected_records
    except Exception:
        return False
