"""Spec-001 US3：旧版格式1库 → 内部格式2的副本升级与旧材料转换（T040–T043）。

安全约定：
- 只升级调用方明确给出的副本；正式 DEK、盐、DEK 密文、字段密文全部原样保留；
- pending 审批以同一 id/op_type 用 DEK 用途密钥整体重保护，内容与状态不变；
- 旧明文 AI 令牌删除，转为「摘要 + DEK 令牌密文」：不轮换令牌、不扩大权限；
- 已处理审批清除旧密文，仅留白名单非敏感审计（op_type/status，时间/结果留空）；
- vault_id/restore_epoch 迁移时新生成，change_seq 从 1 开始；
- 所有结构/数据核验失败都在提交前拒绝；提交只允许在单事务内完成，失败整体回滚；
- 旧 .bin 仅在内存解密转换，绝不写解密临时数据库；主密码不等于旧 DEK 材料。

本模块只做纯数据变换与内存验证，不导入 Flask、不触碰活动库路径选择；
操作生命周期、屏障、备份发布与 HTTP 映射在 app.operations / app.api。
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import closing

from cryptography.exceptions import InvalidTag

from app import crypto
from app import backup as backup_module

# 迁移后首序号：与显式初始化一致（1 = 迁移提交 + 后置首包）
MIGRATION_CHANGE_SEQ = 1

# 确认有效期与恢复一致：5 分钟
MIGRATION_TTL_SECONDS = 300


class MigrationOperation:
    """仅内存的副本升级操作；5 分钟过期，不写 URL/日志/localStorage。"""

    __slots__ = ("snapshot", "digest", "kek", "dek", "old_token", "records_before",
                 "counts", "pre_backup", "post_backup", "confirmation_nonce",
                 "expires_at", "status", "stage")

    def __init__(self, *, snapshot, digest, kek, dek, old_token, records_before,
                 counts, pre_backup):
        self.snapshot = snapshot          # prepare 时认证的格式1快照
        self.digest = digest              # 提交前目标变化检测
        self.kek, self.dek = kek, dek
        self.old_token = old_token
        self.records_before = records_before
        self.counts = counts
        self.pre_backup = pre_backup
        self.post_backup = None
        self.confirmation_nonce = secrets.token_urlsafe(32)
        self.expires_at = time.monotonic() + MIGRATION_TTL_SECONDS
        # prepared → committing → committed → postverified；
        # 提交前失败 failed；提交后核验异常 committed_data_invalid（持久冻结）；
        # 提交成功但后置备份失败 committed_backup_failed（不冻结、可重试）
        self.status = "prepared"
        self.stage = "prebackup_verified"

# 升级前后必须逐行一致的业务表：approvals（重保护）与 meta（身份换代）预期变化
_BUSINESS_TABLES = ("categories", "assets", "fields", "sqlite_sequence")


# ---------- 共享变换（真实副本事务与内存预演共用） ----------


def _approval_columns(conn):
    return {row[1] for row in conn.execute("PRAGMA table_info(approvals)")}


def upgrade_connection(conn, kek, dek, old_token, *, fault=None):
    """在调用方已打开的一个事务内完成 v1→v2 全部写入；不自行提交。

    顺序固定：加列（approvals 保护列 + assets 的 US5 两列）→ pending 重保护 →
    processed 清密文留审计 → meta 换代（删明文令牌、写格式2身份、写令牌摘要/密文）。
    """
    from app import db

    existing = _approval_columns(conn)
    for definition in db.APPROVAL_COLUMNS:
        column = definition.split()[0]
        if column not in existing:
            # 片段来自内置白名单常量，不接受任何外部 SQL
            conn.execute("ALTER TABLE approvals ADD COLUMN " + definition)

    # US5：v1→v2 同事务补齐 assets 的 priority/due_date，旧行取列默认值
    db._reconcile_asset_columns_conn(conn)

    rows = conn.execute(
        "SELECT id,op_type,payload,status FROM approvals ORDER BY id").fetchall()
    approval_key = db._approval_key(old_token)
    for row in rows:
        if row["status"] == "pending":
            protected = json.loads(row["payload"])
            plain = db._unprotect_payload(protected, approval_key)
            if not isinstance(plain, dict):
                raise ValueError("invalid_approval_payload")
            cipher = db.encode_pending(dek, row["id"], row["op_type"], plain)
            conn.execute(
                "UPDATE approvals SET payload=?,protection_version=2 WHERE id=?",
                (cipher, row["id"]))
        elif row["status"] in ("approved", "rejected"):
            # 旧审批结果没有可信的处理时间/结果资产：审计只留 op_type+status
            audit = db.audit_summary(row["op_type"], row["status"])
            conn.execute(
                "UPDATE approvals SET payload='',protection_version=2,"
                "processed_at=NULL,result_asset_id=NULL,audit_summary=? WHERE id=?",
                (crypto.canonical_json(audit), row["id"]))
        else:
            raise ValueError("invalid_approval_status")

    conn.execute("DELETE FROM meta WHERE key='ai_token'")  # 明文令牌不落格式2
    db.write_format2_identity(conn, change_seq=MIGRATION_CHANGE_SEQ)
    db.store_token(conn, dek, old_token)
    if fault is not None:
        fault("migrate_before_commit")


def preview_counts(conn):
    """只返回非敏感计数，供确认页展示；不读任何字段/审批内容。"""
    def count(table):
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return {
        "assets": count("assets"),
        "fields": count("fields"),
        "categories": count("categories"),
        "pending": conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0],
        "processed": conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE status IN ('approved','rejected')"
        ).fetchone()[0],
    }


def business_records_match(before, after):
    """只比较迁移必须保留的业务表；布尔结果，不输出差异内容。

    assets 允许调和式加列：新列固定追加在表尾，旧行按共有列（行前缀）比较；
    新增列的默认值（normal/NULL）由专门用例另行核验。
    """
    for table in _BUSINESS_TABLES:
        old_rows, new_rows = before.get(table), after.get(table)
        if table != "assets":
            if old_rows != new_rows:
                return False
            continue
        if not isinstance(old_rows, list) or not isinstance(new_rows, list):
            return False
        if len(old_rows) != len(new_rows):
            return False
        width = min((len(row) for row in old_rows + new_rows), default=0)
        if any(old[:width] != new[:width] for old, new in zip(old_rows, new_rows)):
            return False
    return True


# ---------- 内存预演（T040） ----------


def _v1_pending_plaintexts(conn, old_token):
    """读出格式1下全部 pending 的明文，作为重保护前后的内容基准。"""
    from app import db
    approval_key = db._approval_key(old_token)
    result = {}
    for row in conn.execute(
            "SELECT id,op_type,payload FROM approvals WHERE status='pending' ORDER BY id"):
        plain = db._unprotect_payload(json.loads(row["payload"]), approval_key)
        if not isinstance(plain, dict):
            raise ValueError("invalid_approval_payload")
        result[row["id"]] = (row["op_type"], plain)
    return result


def _v2_pending_plaintexts(conn, dek):
    from app import db
    result = {}
    for row in conn.execute(
            "SELECT id,op_type,payload FROM approvals WHERE status='pending' ORDER BY id"):
        result[row["id"]] = (row["op_type"],
                             db.decode_pending(dek, row["id"], row["op_type"], row["payload"]))
    return result


def rehearse_upgrade(snapshot, kek, dek):
    """对快照在内存库完整演练一次升级并回读核验；不接触任何数据库文件。

    返回 (升级后快照字节, 迁前逻辑记录, 迁后逻辑记录, 旧令牌)。
    任一审批无法解密、核验失败或业务记录不一致都抛 ValueError（预览拒绝）。
    """
    from app import db

    with db.deserialize_snapshot(snapshot) as source:
        if db.probe_connection(source).state != "legacy_read_only":
            raise ValueError("unsupported_legacy_format")
        old_meta = db.meta_values(source)
        try:
            old_token = old_meta["ai_token"]
            pending_before = _v1_pending_plaintexts(source, old_token)
            records_before = db.validate_records(source, kek, dek)
        except Exception as exc:
            raise ValueError("migration_preview_failed") from exc

    with closing(sqlite3.connect(":memory:")) as scratch:
        scratch.row_factory = sqlite3.Row
        scratch.execute("PRAGMA temp_store=MEMORY")
        scratch.deserialize(snapshot)
        try:
            with db.transaction(scratch):
                upgrade_connection(scratch, kek, dek, old_token)
                db.validate_records(scratch, kek, dek)
            upgraded = scratch.serialize()
        except Exception as exc:
            raise ValueError("migration_preview_failed") from exc

    # 提交后视角重新打开：模拟真实文件提交后的磁盘回读
    with db.deserialize_snapshot(upgraded) as verified:
        records_after = db.validate_records(verified, kek, dek)
        pending_after = _v2_pending_plaintexts(verified, dek)
        meta_after = db.meta_values(verified)

    if pending_after != pending_before:
        raise ValueError("migration_preview_failed")
    if not business_records_match(records_before, records_after):
        raise ValueError("migration_preview_failed")
    for key in ("salt", "dek_encrypted", "password_check"):
        if meta_after[key] != old_meta[key]:
            raise ValueError("migration_preview_failed")
    return upgraded, records_before, records_after, old_token


# ---------- 旧 .bin / schema1 包的内存转换（T043） ----------


def _upgrade_snapshot_in_memory(snapshot, kek, dek):
    """校验 v1 快照 → 内存升级 → 回读核验；返回升级后字节与逻辑记录。"""
    from app import db
    try:
        with db.deserialize_snapshot(snapshot) as source:
            probe = db.probe_connection(source)
            if probe.state != "legacy_read_only":
                raise ValueError("unsupported_legacy_format")
            db.validate_records(source, kek, dek)
        upgraded, _before, records_after, _token = rehearse_upgrade(snapshot, kek, dek)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("legacy_convert_failed") from exc
    return upgraded, records_after


def _seal_manual_package(upgraded_snapshot, records, kek):
    """把内存中的格式2快照封成 manual 新包并在内存回读验证；不落盘。"""
    identity = backup_module.snapshot_identity(upgraded_snapshot)
    blob, header = backup_module.encrypt_package(
        upgraded_snapshot, kek=kek, salt=identity["salt"],
        vault_id=identity["vault_id"], restore_epoch=identity["restore_epoch"],
        change_seq=identity["change_seq"], db_schema_version=2, purpose="manual")
    # 发布前同等强度的回读：解密 + 记录匹配，全部只在内存
    _, readback = backup_module.open_package(blob, kek)
    if not backup_module.records_match(readback, records):
        raise ValueError("legacy_convert_failed")
    return blob, header


def convert_legacy_bin(blob, *, kek, dek):
    """旧 .bin = nonce(12)||AES-GCM(DEK, 明文 SQLite)。

    凭匹配的旧 DEK 仅在内存解密/升级/封包；DEK 不匹配明确抛 legacy_key_required。
    """
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        raise ValueError("invalid_request")
    try:
        snapshot = crypto.decrypt_bytes(dek, bytes(blob))
    except (InvalidTag, ValueError):
        # 认证失败或字节构不构成 nonce+密文：都说明缺少匹配的旧 DEK 材料
        raise ValueError("legacy_key_required") from None
    upgraded, records = _upgrade_snapshot_in_memory(snapshot, kek, dek)
    return _seal_manual_package(upgraded, records, kek)


def convert_schema1_package(blob, *, password):
    """schema1 的 AVBK0002 包：凭包密码解包 → 内存迁移 → schema2 新包。

    密码错误/包损坏统一抛 invalid_credentials_or_corrupt；
    v2 包不属于可转换材料，抛 migration_not_required。
    """
    from app import db
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        raise ValueError("invalid_request")
    if not isinstance(password, str) or not password:
        raise ValueError("invalid_request")
    try:
        header, snapshot = backup_module.decrypt_package(bytes(blob), password)
    except backup_module.BackupError as exc:
        if exc.code == "invalid_credentials_or_corrupt":
            raise ValueError("invalid_credentials_or_corrupt") from None
        raise ValueError("invalid_package") from None
    if header["db_schema_version"] != 1:
        raise ValueError("migration_not_required")
    with db.deserialize_snapshot(snapshot) as conn:
        kek, dek = db.credentials(conn, password)
    upgraded, records = _upgrade_snapshot_in_memory(snapshot, kek, dek)
    return _seal_manual_package(upgraded, records, kek)
