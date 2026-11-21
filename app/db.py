"""数据层：SQLite 建表、读写、会话/令牌。

安全约定：
- 敏感字段（sensitive=1）写入前用 DEK 加密，明文绝不落盘；
- 主密码 / KEK / DEK 只存在于内存会话中；
- 会话 token 只存内存；格式2只存用途隔离令牌密文/摘要。
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from contextlib import contextmanager, closing
from dataclasses import dataclass
from functools import lru_cache
import re
from datetime import date, datetime
from pathlib import Path
from app import crypto, operations

from app.crypto import (
    decrypt_dek,
    decrypt_value,
    derive_kek,
    encrypt_dek,
    encrypt_value,
    generate_dek,
    make_password_check,
    verify_password_check,
)

BASE_DIR = Path(__file__).resolve().parent.parent  # 仅开发模式使用；打包后 static 等资源走 PyInstaller 内部路径

if getattr(sys, "frozen", False):
    # PyInstaller 打包运行时：数据必须落在 exe 所在目录。
    # 不能用 __file__（onefile 模式下指向 _MEIPASS 临时解压目录，软件退出即清空，数据必丢）。
    APP_DIR = Path(sys.executable).resolve().parent
else:
    # 开发模式：项目根目录
    APP_DIR = BASE_DIR
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "vault.db"

MASK = "••••"  # 敏感字段掩码

# 首启预置的 7 个分类：(key, name, icon, sort_order)
DEFAULT_CATEGORIES = [
    ("identity", "账号与通信", "🔐", 1),
    ("ent", "娱乐与社交", "🎮", 2),
    ("career", "职业与教育", "💼", 3),
    ("dev", "开发与基础设施", "⚙️", 4),
    ("ai", "AI 与智能服务", "🤖", 5),
    ("finance", "财务与订阅", "💰", 6),
    ("data", "数据与创作", "📦", 7),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  icon TEXT DEFAULT '🏷️',
  sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category_key TEXT DEFAULT '',
  provider TEXT DEFAULT '',
  status TEXT DEFAULT 'normal',
  risk TEXT DEFAULT 'mid',
  icon TEXT DEFAULT '🏷️',
  tags TEXT DEFAULT '[]',
  depends_on TEXT DEFAULT '[]',
  created_at TEXT,
  updated_at TEXT,
  priority TEXT DEFAULT 'normal',
  due_date TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS fields (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL,
  label TEXT NOT NULL,
  value TEXT NOT NULL,
  sensitive INTEGER DEFAULT 0,
  kind TEXT DEFAULT 'text',
  sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TEXT
);
"""

# 资产表可更新列（排除 id/时间戳）
_ASSET_COLUMNS = (
    "name",
    "category_key",
    "provider",
    "status",
    "risk",
    "icon",
    "tags",
    "depends_on",
    "priority",
    "due_date",
)

# US5：优先级三档枚举（默认 normal），到期日为可空纯日期 YYYY-MM-DD
PRIORITY_VALUES = ("high", "normal", "low")
# 调和式加列片段（内置白名单常量，不接受任何外部 SQL）；列须追加在表末尾，
# 使 ALTER 后的旧库列序与新建库一致，逻辑记录仅末尾多出两列
ASSET_COLUMN_DEFINITIONS = (
    "priority TEXT DEFAULT 'normal'",
    "due_date TEXT DEFAULT NULL",
)
# 加列前的历史 assets 建表语句（Spec-001 v2 时代 10 列），仅用于受信结构指纹
LEGACY_ASSETS_DDL = """
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category_key TEXT DEFAULT '',
  provider TEXT DEFAULT '',
  status TEXT DEFAULT 'normal',
  risk TEXT DEFAULT 'mid',
  icon TEXT DEFAULT '🏷️',
  tags TEXT DEFAULT '[]',
  depends_on TEXT DEFAULT '[]',
  created_at TEXT,
  updated_at TEXT
)
"""
_DUE_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def validate_priority(value):
    """三档枚举校验；缺失由调用方给默认，显式传 None/空串/越界值一律拒绝。"""
    if not isinstance(value, str) or value not in PRIORITY_VALUES:
        raise ValueError("invalid_priority")
    return value


def validate_due_date(value):
    """纯日期校验：None/空串归一为 NULL（清空），非法格式或非真实日历拒绝。"""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _DUE_DATE_RE.fullmatch(value):
        raise ValueError("invalid_due_date")
    try:  # 真实日历校验：闰年 2-29、月份天数、跨年均由 date.fromisoformat 承接
        date.fromisoformat(value)
    except ValueError:
        raise ValueError("invalid_due_date") from None
    return value

# 内存会话：token -> {"kek": bytes, "dek": bytes, "first_run": bool, "created_at": str}
SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()


class CategoryExistsError(ValueError):
    """分类 key 已存在。"""


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@contextmanager
def _conn(*, write=False, change=False, kek=None):
    """One guarded connection; never create a missing DB through a reader.

    change=True 时：事务内由 mark_change 递增一次序号，提交后立刻做内存快照
    和已验证自动备份；备份失败保留已提交数据，返回 saved=true 双结果。
    """
    manager = operations.for_vault(DB_PATH)
    with manager.barrier():
        probe = probe_format(DB_PATH)
        if probe.state not in ('ready_locked', 'legacy_read_only', 'maintenance_failed'):
            raise operations.OperationError('vault_not_ready', 409)
        if write and probe.state != 'ready_locked':
            raise operations.OperationError('vault_read_only', 409)
        frame = None
        with connection(DB_PATH, readonly=not write) as conn:
            if write:
                with transaction(conn):
                    if change:
                        frame = operations.ChangeFrame()
                        conn._change_frame = frame
                    try:
                        yield conn
                    finally:
                        if change:
                            del conn._change_frame
            else:
                yield conn
        if change and frame is not None and frame.seq is not None:
            manager.change_info = manager.finalize_change(kek, frame.seq)


def mark_change(conn):
    """业务事务内：一次持久化改变对应一个 change_seq；无改变不调用。"""
    frame = getattr(conn, '_change_frame', None)
    if frame is None or not conn.in_transaction:
        raise ValueError('transaction_required')
    frame.seq = increment_change_seq(conn)
    return frame.seq


def _parse_json(raw, default):
    try:
        return json.loads(raw or "null")
    except (ValueError, TypeError):
        return default


def _dump_json_list(value) -> str:
    if value is None:
        return "[]"
    if isinstance(value, str):
        return value  # 已是 JSON 字符串则原样保留
    return json.dumps(list(value), ensure_ascii=False)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _approval_key(ai_token: str) -> bytes:
    """审批表敏感字段的独立加密密钥，由 AI 令牌派生（与主密码/DEK 隔离）。"""
    return hashlib.sha256(("asset-vault-approval:" + ai_token).encode("utf-8")).digest()


def init_db():
    """Removed implicit startup writes; initialize explicitly with a password."""
    raise operations.OperationError('explicit_initialization_required', 409)


# ---------- meta ----------


def get_meta(key: str):
    with _conn() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None


def set_meta(key: str, value: str):
    if key not in FORMAT2_META or not isinstance(value, str):
        raise ValueError('unsupported_meta_write')
    with _conn(write=True) as conn:
        conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES (?,?)", (key, value))
        _validate_meta(meta_values(conn), 2)


# ---------- 主密码初始化 / 解锁 ----------


def setup_master_password(password: str):
    """首次设置主密码：生成盐 + KEK + DEK，盐/DEK 密文/校验值落盘，返回 (kek, dek)。"""
    return initialize_vault(password)


def unlock(password: str, *, initialize=False):
    """Never infer creation from a missing salt. Legacy unlock remains read-only."""
    manager = operations.for_vault(DB_PATH)
    with manager.barrier(maintenance=True):
        probe = probe_format(DB_PATH)
        # US5：v2 历史库在任何凭据处理前先做调和式补列，补完复探；
        # 已受信的 v2 结构（含 maintenance_failed）直接调和；只缺一列的中间态
        # 探针只能报 unknown_schema，同样在解锁时凭内置常量修复后复探。
        # v1 旧库维持只读语义，解锁路径绝不写改；新结构库调和为 no-op。
        reconcilable = probe.state in ('ready_locked', 'maintenance_failed') or (
            probe.state == 'unsupported' and probe.code == 'unknown_schema')
        if reconcilable and reconcile_asset_columns(DB_PATH):
            probe = probe_format(DB_PATH)
        first_run = probe.state in ('missing', 'uninitialized')
        vault_id = None
        if first_run:
            if not initialize:
                raise operations.OperationError('explicit_initialization_required', 409)
            kek, dek = initialize_vault(password)
            with connection(DB_PATH, readonly=True) as conn:
                vault_id = meta_values(conn).get('vault_id')
        elif probe.state in ('ready_locked', 'legacy_read_only', 'maintenance_failed'):
            with connection(DB_PATH, readonly=True) as conn:
                kek, dek = credentials(conn, password)
                if probe.state in ('ready_locked', 'maintenance_failed'):
                    vault_id = meta_values(conn).get('vault_id')
        else:
            raise operations.OperationError('vault_not_ready', 409)
        # 登记仅内存解锁状态；会话绑定库身份与代次（US4）
        generation = manager.register_unlock(vault_id)
        token = create_session(kek, dek, first_run,
                               vault_id=vault_id, generation=generation)
        SESSIONS[token]['vault_path'] = str(Path(DB_PATH).resolve())
        # 解锁后按三元组精确核对备份状态；上次提交后未完成时补备份
        if probe.state == 'ready_locked':
            manager.reconcile_backups(kek, dek)
        return token, first_run


# ---------- 会话（内存） ----------


def create_session(kek: bytes, dek: bytes, first_run: bool, *,
                   vault_id=None, generation: int = 0) -> str:
    token = secrets.token_hex(32)  # 32 字节随机
    with _SESSIONS_LOCK:
        SESSIONS[token] = {
            "kek": kek,
            "dek": dek,
            "first_run": first_run,
            "created_at": _now(),
            "vault_id": vault_id,
            "generation": generation,
            "last_activity": time.monotonic(),
        }
    return token


def get_session(token: str):
    with _SESSIONS_LOCK:
        value = SESSIONS.get(token)
        if not value or value.get('vault_path') != str(Path(DB_PATH).resolve()):
            return None
    # 代次/库身份/闲置过期由协调器在操作锁判定；此处不续期
    return value if operations.for_vault(DB_PATH).context_valid(value) else None


def touch_session(token: str):
    """已授权用户操作续期闲置计时；AI 提交路径绝不调用。"""
    with _SESSIONS_LOCK:
        sess = SESSIONS.get(token)
        if sess and sess.get('vault_path') == str(Path(DB_PATH).resolve()):
            sess['last_activity'] = time.monotonic()


def sessions_for_path(path):
    """某库路径下登记的内存会话快照（协调器复查解锁状态用）。"""
    resolved = str(Path(path).resolve())
    with _SESSIONS_LOCK:
        return [sess for sess in SESSIONS.values()
                if sess.get('vault_path') == resolved]


def delete_session(token: str):
    SESSIONS.pop(token, None)


# ---------- 分类 ----------


def list_categories():
    with _conn() as conn:
        rows = conn.execute(
            "SELECT key,name,icon,sort_order FROM categories ORDER BY sort_order ASC, key ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_category(key: str):
    with _conn() as conn:
        row = conn.execute(
            "SELECT key,name,icon,sort_order FROM categories WHERE key=?", (key,)
        ).fetchone()
        return dict(row) if row else None


def create_category(key, name, icon="🏷️", sort_order=0, *, kek=None):
    key = str(key or "").strip()
    if not key or not str(name or "").strip():
        raise ValueError("key 和 name 不能为空")
    try:
        with _conn(write=True, change=True, kek=kek) as conn:
            conn.execute(
                "INSERT INTO categories (key,name,icon,sort_order) VALUES (?,?,?,?)",
                (key, str(name), str(icon or "🏷️"), int(sort_order or 0)),
            )
            mark_change(conn)
    except sqlite3.IntegrityError:
        raise CategoryExistsError("分类 key 已存在")


def update_category(key, name=None, icon=None, sort_order=None, *, kek=None):
    sets, vals = [], []
    if name is not None:
        sets.append("name=?")
        vals.append(str(name))
    if icon is not None:
        sets.append("icon=?")
        vals.append(str(icon))
    if sort_order is not None:
        sets.append("sort_order=?")
        vals.append(int(sort_order))
    if not sets:
        return get_category(key) is not None
    vals.append(key)
    with _conn(write=True, change=True, kek=kek) as conn:
        cur = conn.execute(f"UPDATE categories SET {', '.join(sets)} WHERE key=?", vals)
        changed = cur.rowcount > 0
        if changed:
            mark_change(conn)
        return changed


def delete_category(key: str, *, kek=None) -> bool:
    with _conn(write=True, change=True, kek=kek) as conn:
        cur = conn.execute("DELETE FROM categories WHERE key=?", (key,))
        if cur.rowcount == 0:
            return False
        conn.execute("UPDATE assets SET category_key='' WHERE category_key=?", (key,))
        mark_change(conn)
        return True


# ---------- 资产 ----------


def _field_dict(row, dek):
    d = dict(row)
    if d["sensitive"]:
        # 有 DEK 时返回明文（详情页用）；无 DEK 时返回掩码，防止误暴露
        d["value"] = decrypt_value(dek, d["value"]) if dek else MASK
    return d


def _insert_field(conn, asset_id, field, dek):
    label = str(field.get("label") or "").strip()
    if not label:
        raise ValueError("字段 label 不能为空")
    sensitive = 1 if field.get("sensitive") else 0
    value = str(field.get("value") if field.get("value") is not None else "")
    stored = encrypt_value(dek, value) if sensitive else value
    conn.execute(
        "INSERT INTO fields (asset_id,label,value,sensitive,kind,sort_order) VALUES (?,?,?,?,?,?)",
        (
            asset_id,
            label,
            stored,
            sensitive,
            str(field.get("kind") or "text"),
            int(field.get("sort_order") or 0),
        ),
    )


def _asset_dict(row, conn, dek):
    asset = dict(row)
    asset["tags"] = _parse_json(asset["tags"], [])
    asset["depends_on"] = _parse_json(asset["depends_on"], [])
    fields = conn.execute(
        "SELECT * FROM fields WHERE asset_id=? ORDER BY sort_order ASC, id ASC",
        (asset["id"],),
    ).fetchall()
    asset["fields"] = [_field_dict(f, dek) for f in fields]
    return asset


def create_asset(dek, data, *, kek=None) -> int:
    """创建资产（含字段）；敏感字段在此加密落盘。返回新资产 id。"""
    name = str(data.get("name") or "").strip()
    if not name:
        raise ValueError("name 不能为空")
    # US5：优先级/到期日落库前先过枚举与真实日历校验；未传则取列默认值
    priority = validate_priority(data["priority"]) if "priority" in data else "normal"
    due_date = validate_due_date(data["due_date"]) if "due_date" in data else None
    now = _now()
    with _conn(write=True, change=True, kek=kek) as conn:
        cur = conn.execute(
            "INSERT INTO assets (name,category_key,provider,status,risk,icon,tags,depends_on,"
            "created_at,updated_at,priority,due_date)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                name,
                str(data.get("category_key") or ""),
                str(data.get("provider") or ""),
                str(data.get("status") or "normal"),
                str(data.get("risk") or "mid"),
                str(data.get("icon") or "🏷️"),
                _dump_json_list(data.get("tags")),
                _dump_json_list(data.get("depends_on")),
                now,
                now,
                priority,
                due_date,
            ),
        )
        asset_id = cur.lastrowid
        for field in data.get("fields") or []:
            _insert_field(conn, asset_id, field, dek)
        mark_change(conn)
    return asset_id


def get_asset(asset_id, dek=None):
    with _conn() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            return None
        return _asset_dict(row, conn, dek)


def list_assets(dek=None):
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM assets ORDER BY id ASC").fetchall()
        return [_asset_dict(r, conn, dek) for r in rows]


def update_asset(asset_id, dek, data, *, kek=None):
    """部分更新：只改 body 中出现的列；body 带 fields 时整体替换字段集。"""
    with _conn(write=True, change=True, kek=kek) as conn:
        row = conn.execute("SELECT id FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            return None
        sets, vals = [], []
        for col in _ASSET_COLUMNS:
            if col in data:
                val = data[col]
                if col in ("tags", "depends_on"):
                    val = _dump_json_list(val)
                elif col == "priority":
                    val = validate_priority(val)
                elif col == "due_date":
                    val = validate_due_date(val)  # None/空串归一为 SQL NULL，绝不写成 'None'
                else:
                    val = str(val)
                sets.append(f"{col}=?")
                vals.append(val)
        sets.append("updated_at=?")
        vals.append(_now())
        vals.append(asset_id)
        conn.execute(f"UPDATE assets SET {', '.join(sets)} WHERE id=?", vals)
        if "fields" in data:
            conn.execute("DELETE FROM fields WHERE asset_id=?", (asset_id,))
            for field in data["fields"]:
                _insert_field(conn, asset_id, field, dek)
        mark_change(conn)
    return get_asset(asset_id, dek)


def delete_asset(asset_id, *, kek=None) -> bool:
    with _conn(write=True, change=True, kek=kek) as conn:
        conn.execute("DELETE FROM fields WHERE asset_id=?", (asset_id,))
        cur = conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
        if cur.rowcount == 0:
            return False
        mark_change(conn)
        return True


def search(q, dek=None):
    """搜索：匹配 name / provider / 非敏感字段明文 value。"""
    q = (q or "").strip()
    if not q:
        return []
    pattern = "%" + _escape_like(q) + "%"
    with _conn() as conn:
        rows = conn.execute(
            "SELECT a.id FROM assets a WHERE a.name LIKE ? ESCAPE '\\' OR a.provider LIKE ? ESCAPE '\\'"
            " UNION"
            " SELECT asset_id AS id FROM fields WHERE sensitive=0 AND value LIKE ? ESCAPE '\\'",
            (pattern, pattern, pattern),
        ).fetchall()
        ids = [r["id"] for r in rows]
    return [get_asset(i, dek) for i in ids]


# ---------- 审批 ----------


def _protect_payload(payload, key):
    """把 payload 中敏感字段值加密（审批落盘前调用，防止明文进 vault.db）。"""
    if isinstance(payload, dict):
        if payload.get("sensitive") and "value" in payload:
            out = dict(payload)
            out["value"] = encrypt_value(key, str(payload.get("value") or ""))
            return out
        return {k: _protect_payload(v, key) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_protect_payload(v, key) for v in payload]
    return payload


def _unprotect_payload(payload, key):
    """审批批准时解出明文 payload。"""
    if isinstance(payload, dict):
        if payload.get("sensitive") and "value" in payload:
            out = dict(payload)
            out["value"] = decrypt_value(key, out["value"])
            return out
        return {k: _unprotect_payload(v, key) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_unprotect_payload(v, key) for v in payload]
    return payload


def create_ai_approval(op_type: str, payload, *, dek, kek) -> int:
    """AI 请求在用户有效解锁窗口内：单事务加密保存 pending + 一个序号；
    不直接写资产。提交后由 _conn 统一做已验证自动备份。"""
    with _conn(write=True, change=True, kek=kek) as conn:
        approval_id = store_pending(conn, dek, op_type, payload)
        mark_change(conn)
    return approval_id


def _approval_dict(row, dek):
    d = dict(row)
    if d.get('status') == 'pending' and d.get('protection_version') == 2:
        # 仅在持有会话 DEK 时整体解密；API 层再做敏感掩码
        d['payload'] = decode_pending(dek, d['id'], d['op_type'], d['payload'])
    else:
        d['payload'] = _parse_json(d['payload'], {})
    return d


def list_approvals(dek):
    """待审批列表；用会话 DEK 解码 payload（敏感值由 API 层掩码展示）。"""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM approvals WHERE status='pending' ORDER BY id ASC"
        ).fetchall()
        return [_approval_dict(r, dek) for r in rows]


def list_approval_history(limit=30):
    """已处理审批的非敏感审计记录（操作类型/批准或拒绝/处理时间/结果资产 id）。

    终端记录 payload 已在处理时清空，密码等敏感值不可恢复——历史区本就只能
    回答「什么时候批准/拒绝了什么操作」，不能回看提交内容。
    """
    limit = max(1, min(int(limit), 100))
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id,op_type,status,processed_at,result_asset_id FROM approvals "
            "WHERE status IN ('approved','rejected') ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [{'id': row['id'], 'op_type': row['op_type'], 'status': row['status'],
                 'processed_at': row['processed_at'],
                 'result_asset_id': row['result_asset_id']} for row in rows]


def get_approval(approval_id, dek=None):
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM approvals WHERE id=?", (approval_id,)
        ).fetchone()
        if not row:
            return None
        return _approval_dict(row, dek) if dek else dict(row)


def _apply_approval(conn, dek, op_type, payload):
    """批准时在审批事务的同一连接/事务内落资产变更；返回 result_asset_id。

    任何异常都随审批事务整体回滚，pending 保留可重试或拒绝。
    """
    if op_type == 'create':
        name = str(payload.get('name') or '').strip()
        if not name:
            raise ValueError('name 不能为空')
        # US5：AI 提交时不校验，批准落库瞬间才与手动路径共用同一套枚举/日历校验
        priority = validate_priority(payload["priority"]) if "priority" in payload else "normal"
        due_date = validate_due_date(payload["due_date"]) if "due_date" in payload else None
        now = _now()
        cur = conn.execute(
            "INSERT INTO assets (name,category_key,provider,status,risk,icon,tags,depends_on,"
            "created_at,updated_at,priority,due_date)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                name,
                str(payload.get("category_key") or ""),
                str(payload.get("provider") or ""),
                str(payload.get("status") or "normal"),
                str(payload.get("risk") or "mid"),
                str(payload.get("icon") or "🏷️"),
                _dump_json_list(payload.get("tags")),
                _dump_json_list(payload.get("depends_on")),
                now,
                now,
                priority,
                due_date,
            ),
        )
        asset_id = cur.lastrowid
        for field in payload.get('fields') or []:
            _insert_field(conn, asset_id, field, dek)
        return asset_id
    if op_type not in ('update', 'delete'):
        raise ValueError('op_type 必须是 create/update/delete')
    try:
        asset_id = int(payload.get('id'))
    except (TypeError, ValueError):
        raise ValueError('id 必须是正整数') from None
    if asset_id <= 0:
        raise ValueError('id 必须是正整数')
    if op_type == 'delete':
        conn.execute("DELETE FROM fields WHERE asset_id=?", (asset_id,))
        cur = conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
        if cur.rowcount == 0:
            raise operations.OperationError('approval_target_not_found', 404)
        return asset_id
    if not conn.execute("SELECT 1 FROM assets WHERE id=?", (asset_id,)).fetchone():
        raise operations.OperationError('approval_target_not_found', 404)
    sets, vals = [], []
    for col in _ASSET_COLUMNS:
        if col in payload:
            val = payload[col]
            if col in ("tags", "depends_on"):
                val = _dump_json_list(val)
            elif col == "priority":
                val = validate_priority(val)
            elif col == "due_date":
                val = validate_due_date(val)  # 清空显式落 NULL
            else:
                val = str(val)
            sets.append(f"{col}=?")
            vals.append(val)
    sets.append("updated_at=?")
    vals.append(_now())
    vals.append(asset_id)
    conn.execute(f"UPDATE assets SET {', '.join(sets)} WHERE id=?", vals)
    if "fields" in payload:
        conn.execute("DELETE FROM fields WHERE asset_id=?", (asset_id,))
        for field in payload["fields"]:
            _insert_field(conn, asset_id, field, dek)
    return asset_id


def process_approval(approval_id, decision, *, dek, kek, fault=None):
    """批准/拒绝一个事务内完成：读 pending →（批准则写资产）→ 终态/清 payload
    → audit 白名单 → 一次 change_seq。失败整体回滚，pending 保留。"""
    if decision not in ('approved', 'rejected'):
        raise ValueError('invalid_decision')
    with _conn(write=True, change=True, kek=kek) as conn:
        row = conn.execute(
            "SELECT id,op_type,payload,status,protection_version FROM approvals WHERE id=?",
            (approval_id,)).fetchone()
        if not row:
            raise operations.OperationError('approval_not_found', 404)
        if row['status'] != 'pending' or row['protection_version'] != 2:
            raise operations.OperationError('approval_already_processed', 409)
        payload = decode_pending(dek, row['id'], row['op_type'], row['payload'])
        asset_id = None
        if decision == 'approved':
            asset_id = _apply_approval(conn, dek, row['op_type'], payload)
            if fault:
                fault('after_asset_write')
        store_terminal(conn, approval_id, decision,
                       processed_at=_now(), result_asset_id=asset_id)
        if fault:
            fault('before_commit')
        mark_change(conn)
        return asset_id


# ---------- AI 令牌 ----------


def get_ai_token_hash():
    """只读返回域分隔令牌摘要（身份恒定时间比对用），不接触密文/DEK。"""
    with _conn() as conn:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='ai_token_hash'").fetchone()
        return row['value'] if row else None


def reveal_ai_token(dek):
    """用户已解锁：用 DEK 令牌用途密钥解密当前 AI 令牌明文（仅展示给用户）。"""
    with _conn() as conn:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='ai_token_encrypted'").fetchone()
        if not row:
            raise operations.OperationError('ai_token_unavailable', 409)
        return crypto.decrypt_aad(crypto.purpose_key(dek, 'token'), row['value'],
                                  crypto.TOKEN_AAD).decode('utf-8')


def reset_ai_token(*, dek, kek) -> str:
    """同事务换摘要/密文：不动任何 pending（审批保护由 DEK 用途密钥负责）。"""
    token = secrets.token_hex(32)
    with _conn(write=True, change=True, kek=kek) as conn:
        store_token(conn, dek, token)
        mark_change(conn)
    return token


# ---------- 备份 ----------


def export_db_bytes() -> bytes:
    """A full snapshot remains in memory. New authenticated packages arrive in US2."""
    return snapshot_bytes(DB_PATH)


def import_db_bytes(blob: bytes):
    """Never replace an active file. Confirmed transactional restore arrives in US2."""
    raise operations.OperationError('confirmation_required', 409)


# ---------- Spec-001 Foundation (format 2, not a migration implementation) ----------

FORMAT_VERSION = 2
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
APPROVAL_COLUMNS = ('protection_version INTEGER', 'processed_at TEXT',
                    'result_asset_id INTEGER', 'audit_summary TEXT')
LEGACY_META = frozenset(('salt', 'dek_encrypted', 'password_check', 'ai_token', 'schema_version'))
FORMAT2_META = frozenset(('salt', 'dek_encrypted', 'password_check', 'schema_version',
                         'change_seq', 'vault_id', 'restore_epoch', 'ai_token_hash',
                         'ai_token_encrypted', 'approval_protection_version', 'maintenance_failure'))
REQUIRED2_META = FORMAT2_META - {'maintenance_failure'}


@dataclass(frozen=True)
class FormatProbe:
    state: str
    version: int | None = None
    code: str | None = None


class VaultConnection(sqlite3.Connection):
    def executescript(self, sql):
        if self.in_transaction:
            raise operations.OperationError('executescript_in_transaction', 409)
        return super().executescript(sql)


@contextmanager
def connection(path, *, readonly=False, create=False):
    """Tracked, short-lived connection; process barrier covers its full lifetime."""
    path = Path(path).resolve()
    manager = operations.for_vault(path)
    with manager.lock:
        if not create and not path.is_file():
            raise operations.OperationError('vault_missing', 409)
        target = path.as_uri() + '?mode=ro' if readonly else str(path)
        conn = sqlite3.connect(target, uri=readonly, timeout=10, isolation_level=None,
                               factory=VaultConnection)
        manager.connections.add(conn)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.execute('PRAGMA temp_store=MEMORY')
            if readonly:
                conn.execute('PRAGMA query_only=ON')
            else:
                if conn.execute('PRAGMA journal_mode=DELETE').fetchone()[0] != 'delete':
                    raise operations.OperationError('journal_mode_unavailable', 503)
                conn.execute('PRAGMA synchronous=FULL')
            yield conn
        finally:
            conn.close()
            manager.connections.discard(conn)


@contextmanager
def transaction(conn):
    """Join an existing transaction; only its outer owner may commit or rollback."""
    owner = not conn.in_transaction
    if owner:
        conn.execute('BEGIN IMMEDIATE')
    try:
        yield conn
        if owner:
            conn.commit()
    except BaseException:
        if owner:
            conn.rollback()
        raise


def create_schema(conn, version=2):
    # Trusted built-in statements, individually executed without implicit commit.
    if version not in (1, 2):
        raise ValueError('unsupported_format')
    for statement in SCHEMA.split(';'):
        if statement.strip():
            conn.execute(statement)
    if version == 2:
        for definition in APPROVAL_COLUMNS:
            conn.execute('ALTER TABLE approvals ADD COLUMN ' + definition)


def _reconcile_asset_columns_conn(conn):
    """在调用方已打开的连接/事务内补齐 assets 调和列；返回是否执行过 ALTER。

    列定义只取自内置白名单常量 ASSET_COLUMN_DEFINITIONS，不接受任何外部 SQL；
    已存在的列跳过、缺哪列补哪列，天然幂等。新列追加在表尾，旧行由 SQLite
    自动取列默认值（priority='normal'、due_date=NULL），不触碰任何业务字段。
    """
    existing = {row[1] for row in conn.execute('PRAGMA table_info(assets)')}
    changed = False
    for definition in ASSET_COLUMN_DEFINITIONS:
        column = definition.split()[0]
        if column not in existing:
            conn.execute('ALTER TABLE assets ADD COLUMN ' + definition)
            existing.add(column)
            changed = True
    return changed


def reconcile_asset_columns(path=None):
    """US5：历史库解锁/迁移前的调和入口。

    文件缺失 no-op（首启场景交给显式初始化）；否则用可写短连接幂等补列。
    只读 URI 连接不能执行 ALTER，因此这里绝不能传 readonly=True。
    """
    target = Path(DB_PATH if path is None else path).resolve()
    if not target.is_file():
        return False
    with connection(target) as conn:
        return _reconcile_asset_columns_conn(conn)


def _schema_fingerprint(conn):
    return tuple((r[0], r[1], r[2], re.sub(r'\s+', ' ', r[3] or '').strip())
                 for r in conn.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'))


@lru_cache(maxsize=2)
def _allowed_schema(version):
    with closing(sqlite3.connect(':memory:')) as conn:
        create_schema(conn, version)
        return _schema_fingerprint(conn)


@lru_cache(maxsize=1)
def _historical_fingerprints():
    """US5 加列前后的受信历史结构指纹：{指纹: 格式版本}。

    ALTER ADD COLUMN 会让 SQLite 重写 sqlite_master 中的建表文本，因此调和后
    库的指纹既不等于历史建表文本、也不等于新建库文本。这里在内存库中按与真实
    库完全相同的过程（历史 10 列 DDL → 调和补两列）预算 v1/v2 各一对指纹，
    作为 probe 在现行指纹之外的附加白名单；白名单只来自内置常量，不接受外部输入。
    """
    mapped = {}
    for version in (1, 2):
        with closing(sqlite3.connect(':memory:')) as conn:
            create_schema(conn, version)
            conn.execute('DROP TABLE assets')
            conn.execute(LEGACY_ASSETS_DDL)
            mapped[_schema_fingerprint(conn)] = version  # 调和前：10 列历史库
            for definition in ASSET_COLUMN_DEFINITIONS:
                conn.execute('ALTER TABLE assets ADD COLUMN ' + definition)
            mapped[_schema_fingerprint(conn)] = version  # 调和后：SQLite 重写文本
    return mapped


def meta_values(conn):
    return dict(conn.execute('SELECT key,value FROM meta'))


def _salt(meta):
    raw = base64.b64decode(meta['salt'].encode('ascii'), validate=True)
    if len(raw) != 16 or base64.b64encode(raw).decode('ascii') != meta['salt']:
        raise ValueError('invalid_salt')
    return raw


def _validate_meta(meta, version):
    _salt(meta)
    crypto.decode_cipher(meta['dek_encrypted'], 32)
    crypto.decode_cipher(meta['password_check'], len(crypto.PASSWORD_CHECK))
    if version == 1:
        if not re.fullmatch('[0-9a-f]{64}', meta['ai_token']):
            raise ValueError('invalid_legacy_token')
    else:
        if not REQUIRED2_META <= meta.keys():
            raise ValueError('partial_meta')
        for key in ('vault_id', 'restore_epoch'):
            if str(uuid.UUID(meta[key])) != meta[key] or uuid.UUID(meta[key]).version != 4:
                raise ValueError('invalid_vault_identity')
        if not re.fullmatch('0|[1-9][0-9]*', meta['change_seq']) or int(meta['change_seq']) > 2**63-1:
            raise ValueError('invalid_change_seq')
        if meta['approval_protection_version'] != '2' or not re.fullmatch('[0-9a-f]{64}', meta['ai_token_hash']):
            raise ValueError('invalid_protection_meta')
        crypto.decode_cipher(meta['ai_token_encrypted'], 64)
        if 'maintenance_failure' in meta and meta['maintenance_failure'] != 'committed_data_invalid':
            raise ValueError('invalid_maintenance_marker')


def probe_connection(conn, *, allow_empty=False):
    """Inspect only. Never execute SQL from an uploaded snapshot or stored schema."""
    try:
        objects = _schema_fingerprint(conn)
        pragma = conn.execute('PRAGMA user_version').fetchone()[0]
        if not objects:
            return FormatProbe('uninitialized' if allow_empty and pragma == 0 else 'corrupt', code='empty_database')
        historical = _historical_fingerprints()
        if objects not in (_allowed_schema(1), _allowed_schema(2)) and objects not in historical:
            return FormatProbe('unsupported', code='unknown_schema')
        # Reject foreign SQL objects before asking SQLite to traverse them.
        if [r[0] for r in conn.execute('PRAGMA integrity_check')] != ['ok']:
            return FormatProbe('corrupt', code='integrity_failed')
        meta = meta_values(conn)
        declared = meta.get('schema_version')
        is_v1_shape = objects == _allowed_schema(1) or historical.get(objects) == 1
        is_v2_shape = objects == _allowed_schema(2) or historical.get(objects) == 2
        if declared in (None, '0') and pragma == 0 and is_v1_shape:
            version = 1
        elif declared == '2' and pragma == 2 and is_v2_shape:
            version = 2
        else:
            return FormatProbe('unsupported', code='version_mismatch')
        if not meta.keys() <= (LEGACY_META if version == 1 else FORMAT2_META):
            return FormatProbe('unsupported', code='unknown_meta')
        _validate_meta(meta, version)
        if version == 1:
            return FormatProbe('legacy_read_only', 1)
        return FormatProbe('maintenance_failed' if 'maintenance_failure' in meta else 'ready_locked', 2)
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError, UnicodeError):
        return FormatProbe('corrupt', code='invalid_database')


def initialization_marker(path):
    return Path(path).with_suffix(Path(path).suffix + '.initializing')


def _initialization_incomplete(path):
    marker = initialization_marker(path)
    return (not marker.is_symlink() and marker.is_file()
            and marker.read_bytes() == b'explicit-initialization-incomplete')


def probe_format(path=None):
    path = Path(DB_PATH if path is None else path).resolve()
    if not path.exists():
        return FormatProbe('missing')
    try:
        with connection(path, readonly=True) as conn:
            return probe_connection(conn, allow_empty=_initialization_incomplete(path))
    except (sqlite3.DatabaseError, OSError):
        return FormatProbe('corrupt', code='database_unreadable')


def credentials(conn, password):
    try:
        meta = meta_values(conn)
        kek = derive_kek(password, _salt(meta))
        if not verify_password_check(kek, meta['password_check']):
            raise ValueError()
        dek = decrypt_dek(kek, meta['dek_encrypted'])
        if len(dek) != 32:
            raise ValueError()
        return kek, dek
    except Exception:
        raise ValueError('invalid_credentials_or_corrupt') from None


def write_format2_identity(conn, *, vault_id=None, change_seq=0):
    """Call inside a business transaction. Restore always gets a fresh epoch."""
    if not conn.in_transaction or type(change_seq) is not int or not 0 <= change_seq <= 2**63-1:
        raise ValueError('transaction_required')
    if vault_id is not None and (str(uuid.UUID(vault_id)) != vault_id or uuid.UUID(vault_id).version != 4):
        raise ValueError('invalid_vault_identity')
    values = {'schema_version': '2', 'vault_id': vault_id or str(uuid.uuid4()),
              'restore_epoch': str(uuid.uuid4()), 'change_seq': str(change_seq),
              'approval_protection_version': '2'}
    conn.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', values.items())
    conn.execute('PRAGMA user_version=2')
    return values


def increment_change_seq(conn):
    if not conn.in_transaction:
        raise ValueError('transaction_required')
    current = int(meta_values(conn)['change_seq'])
    if current >= 2**63-1:
        raise ValueError('change_seq_exhausted')
    conn.execute("UPDATE meta SET value=? WHERE key='change_seq'", (str(current + 1),))
    return current + 1


def store_token(conn, dek, token):
    if not conn.in_transaction or not re.fullmatch('[0-9a-f]{64}', token):
        raise ValueError('invalid_token_write')
    values = {'ai_token_hash': crypto.token_digest(token),
              'ai_token_encrypted': crypto.encrypt_aad(crypto.purpose_key(dek, 'token'), token.encode(), crypto.TOKEN_AAD)}
    conn.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', values.items())


def encode_pending(dek, approval_id, op_type, payload):
    if not isinstance(payload, dict):
        raise ValueError('invalid_payload')
    return crypto.encrypt_aad(crypto.purpose_key(dek, 'approval'),
                              crypto.canonical_json(payload).encode('utf-8'), crypto.approval_aad(approval_id, op_type))


def decode_pending(dek, approval_id, op_type, payload):
    decoded = json.loads(crypto.decrypt_aad(crypto.purpose_key(dek, 'approval'), payload,
                                           crypto.approval_aad(approval_id, op_type)))
    if not isinstance(decoded, dict):
        raise ValueError('invalid_payload')
    return decoded


def audit_summary(op_type, status, processed_at=None, result_asset_id=None):
    if op_type not in ('create', 'update', 'delete') or status not in ('approved', 'rejected'):
        raise ValueError('invalid_audit_state')
    if processed_at is not None and not isinstance(processed_at, str):
        raise ValueError('invalid_audit_time')
    if result_asset_id is not None and (type(result_asset_id) is not int or result_asset_id <= 0):
        raise ValueError('invalid_audit_result')
    return {'op_type': op_type, 'status': status, 'processed_at': processed_at, 'result_asset_id': result_asset_id}


def store_pending(conn, dek, op_type, payload):
    """Persistence primitive only; caller owns one transaction and one sequence increment."""
    if not conn.in_transaction:
        raise ValueError('transaction_required')
    cur = conn.execute('INSERT INTO approvals (op_type,payload,status,created_at,protection_version) '
                       "VALUES (?,'','pending',?,2)", (op_type, _now()))
    approval_id = cur.lastrowid
    cipher = encode_pending(dek, approval_id, op_type, payload)
    conn.execute('UPDATE approvals SET payload=? WHERE id=?', (cipher, approval_id))
    return approval_id


def store_terminal(conn, approval_id, status, *, processed_at=None, result_asset_id=None):
    if not conn.in_transaction:
        raise ValueError('transaction_required')
    row = conn.execute('SELECT op_type,status FROM approvals WHERE id=?', (approval_id,)).fetchone()
    if not row or row['status'] != 'pending':
        raise operations.OperationError('approval_already_processed', 409)
    audit = audit_summary(row['op_type'], status, processed_at, result_asset_id)
    conn.execute("UPDATE approvals SET status=?,payload='',processed_at=?,result_asset_id=?,audit_summary=? WHERE id=?",
                 (status, processed_at, result_asset_id, crypto.canonical_json(audit), approval_id))


def initialize_vault(password, *, fault=None):
    """Exclusive explicit creation; keys, identity and categories commit together."""
    if not isinstance(password, str) or not password:
        raise ValueError('invalid_password')
    path = Path(DB_PATH).resolve()
    with operations.for_vault(path).barrier(maintenance=True):
        state = probe_format(path).state
        if state not in ('missing', 'uninitialized'):
            raise operations.OperationError('initialization_not_allowed', 409)
        path.parent.mkdir(parents=True, exist_ok=True)
        marker = initialization_marker(path)
        if state == 'missing':
            if marker.exists():
                if not _initialization_incomplete(path):
                    raise operations.OperationError('initialization_marker_invalid', 409)
            else:
                with marker.open('xb') as stream:
                    stream.write(b'explicit-initialization-incomplete'); stream.flush(); os.fsync(stream.fileno())
            with path.open('xb'):
                pass
        salt, dek = os.urandom(16), generate_dek()
        kek = derive_kek(password, salt)
        with connection(path, create=True) as conn, transaction(conn):
            create_schema(conn)
            if fault: fault('after_schema')
            values = {'salt': base64.b64encode(salt).decode('ascii'),
                      'dek_encrypted': encrypt_dek(kek, dek), 'password_check': make_password_check(kek)}
            conn.executemany('INSERT INTO meta VALUES (?,?)', values.items())
            write_format2_identity(conn, change_seq=1)
            store_token(conn, dek, secrets.token_hex(32))
            conn.executemany('INSERT INTO categories VALUES (?,?,?,?)', DEFAULT_CATEGORIES)
            if fault: fault('before_commit')
            validate_records(conn, kek, dek)
        marker.unlink(missing_ok=True)
        # 初始化也是一次持久化改变：change_seq=1，随后建立首份已验证备份；
        # 备份失败保留已初始化数据，返回双结果
        manager = operations.for_vault(path)
        manager.change_info = manager.finalize_change(kek, 1)
        return kek, dek


def rewrap_master_password(conn, *, new_password, dek):
    """改密事务内核（US3 T044）：新密码+既有盐派生新 KEK，重包同一 DEK。

    必须由调用方在业务事务内调用；任一步失败随外层事务整体回滚，旧密码继续
    有效，不存在半成品密钥状态。不变项：DEK 明文、salt、KDF 参数/迭代数、
    vault_id、v2 格式；变化项：dek_encrypted、password_check、restore_epoch
    （全新 uuid4 代次）、change_seq 递增。返回 (new_kek, new_seq)。
    """
    if not conn.in_transaction:
        raise ValueError('transaction_required')
    if not isinstance(new_password, str) or not new_password:
        raise ValueError('invalid_password')
    if not isinstance(dek, bytes) or len(dek) != 32:
        raise ValueError('invalid_dek')
    meta = meta_values(conn)
    salt = _salt(meta)
    vault_id = meta['vault_id']
    new_kek = derive_kek(new_password, salt)
    values = {
        # 同一 DEK 的新 KEK 包装与新密码校验值
        'dek_encrypted': encrypt_dek(new_kek, dek),
        'password_check': make_password_check(new_kek),
        # 换代：vault_id 保留，restore_epoch 换全新 uuid4
        'restore_epoch': str(uuid.uuid4()),
    }
    conn.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', values.items())
    new_seq = increment_change_seq(conn)
    after = meta_values(conn)
    if after['vault_id'] != vault_id:
        raise ValueError('vault_identity_changed')
    # 提交前全量 meta 校验：v2 合法、身份/序号/加密材料格式全部成立
    _validate_meta(after, 2)
    return new_kek, new_seq


def logical_records(conn):
    """Raw, exact records, including sequences. Never return these in logs/API."""
    result = {}
    for table, order in (('meta', 'key'), ('categories', 'key'), ('assets', 'id'),
                         ('fields', 'id'), ('approvals', 'id'), ('sqlite_sequence', 'name')):
        result[table] = [tuple(r) for r in conn.execute(f'SELECT * FROM {table} ORDER BY {order}')]
    return result


def _validate_column_types(conn):
    """Validate every stored value without normalizing nullable legacy fields.

    Referential gaps are intentionally allowed: old dangling dependencies and
    absent categories must survive logical matching. Keys themselves are typed.
    """
    for table in ('categories', 'assets', 'fields', 'approvals'):
        columns = list(conn.execute(f'PRAGMA table_info({table})'))
        for row in conn.execute(f'SELECT * FROM {table}'):
            for col in columns:
                value = row[col['name']]
                if value is None:
                    if col['notnull'] or col['pk']:
                        raise ValueError('null_required_record_value')
                elif col['type'] == 'INTEGER' and type(value) is not int:
                    raise ValueError('invalid_integer_record_value')
                elif col['type'] == 'TEXT' and not isinstance(value, str):
                    raise ValueError('invalid_text_record_value')
            if table != 'categories' and row['id'] <= 0:
                raise ValueError('invalid_record_id')


def validate_records(conn, kek, dek):
    probe = probe_connection(conn)
    if probe.version not in (1, 2) or probe.state not in ('legacy_read_only', 'ready_locked', 'maintenance_failed'):
        raise ValueError('invalid_snapshot_schema')
    meta = meta_values(conn)
    try:
        _validate_column_types(conn)
        if not verify_password_check(kek, meta['password_check']) or not hmac.compare_digest(decrypt_dek(kek, meta['dek_encrypted']), dek):
            raise ValueError('invalid_snapshot_credentials')
        for row in conn.execute('SELECT * FROM assets'):
            if type(row['id']) is not int or row['id'] <= 0 or not isinstance(row['name'], str):
                raise ValueError('invalid_asset_record')
            for column in ('tags', 'depends_on'):
                if not isinstance(json.loads(row[column]), list):
                    raise ValueError('invalid_asset_list')
        for row in conn.execute('SELECT * FROM fields'):
            if row['sensitive'] not in (0, 1) or not isinstance(row['value'], str):
                raise ValueError('invalid_field_record')
            if row['sensitive']:
                crypto.decode_cipher(row['value'])
                decrypt_value(dek, row['value'])
        if probe.version == 2:
            token = crypto.decrypt_aad(crypto.purpose_key(dek, 'token'), meta['ai_token_encrypted'], crypto.TOKEN_AAD).decode('utf-8')
            if not re.fullmatch('[0-9a-f]{64}', token) or not hmac.compare_digest(crypto.token_digest(token), meta['ai_token_hash']):
                raise ValueError('invalid_snapshot_token')
        for row in conn.execute('SELECT * FROM approvals'):
            if row['op_type'] not in ('create', 'update', 'delete') or row['status'] not in ('pending', 'approved', 'rejected'):
                raise ValueError('invalid_approval_record')
            if probe.version == 1:
                _unprotect_payload(json.loads(row['payload']), _approval_key(meta['ai_token']))
            elif row['protection_version'] != 2:
                raise ValueError('invalid_approval_protection')
            elif row['status'] == 'pending':
                decode_pending(dek, row['id'], row['op_type'], row['payload'])
                if any(row[key] is not None for key in ('audit_summary', 'processed_at', 'result_asset_id')):
                    raise ValueError('invalid_pending_audit')
            else:
                expected = audit_summary(row['op_type'], row['status'], row['processed_at'], row['result_asset_id'])
                if row['payload'] != '' or json.loads(row['audit_summary']) != expected:
                    raise ValueError('invalid_terminal_audit')
        maxima = {t: conn.execute(f'SELECT COALESCE(MAX(id),0) FROM {t}').fetchone()[0]
                  for t in ('assets', 'fields', 'approvals')}
        sequences = dict(conn.execute('SELECT name,seq FROM sqlite_sequence'))
        if not sequences.keys() <= maxima.keys():
            raise ValueError('invalid_sequence_table')
        for table, maximum in maxima.items():
            value = sequences.get(table, 0)
            if type(value) is not int or value < maximum:
                raise ValueError('invalid_sequence')
        return logical_records(conn)
    except Exception:
        raise ValueError('invalid_snapshot_records_or_credentials') from None


def snapshot_bytes(path=None):
    path = Path(DB_PATH if path is None else path).resolve()
    with operations.for_vault(path).barrier(maintenance=True), connection(path, readonly=True) as source:
        if probe_connection(source).version not in (1, 2):
            raise ValueError('invalid_snapshot_schema')
        size = source.execute('PRAGMA page_count').fetchone()[0] * source.execute('PRAGMA page_size').fetchone()[0]
        if size > MAX_SNAPSHOT_BYTES:
            raise ValueError('snapshot_too_large')
        with closing(sqlite3.connect(':memory:')) as target:
            target.execute('PRAGMA temp_store=MEMORY')
            source.backup(target)
            size = target.execute('PRAGMA page_count').fetchone()[0] * target.execute('PRAGMA page_size').fetchone()[0]
            if size > MAX_SNAPSHOT_BYTES:
                raise ValueError('snapshot_too_large')
            return target.serialize()


@contextmanager
def deserialize_snapshot(blob):
    if not isinstance(blob, bytes) or len(blob) > MAX_SNAPSHOT_BYTES or not blob.startswith(b'SQLite format 3\0'):
        raise ValueError('invalid_snapshot_boundary')
    with closing(sqlite3.connect(':memory:')) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA temp_store=MEMORY')
        conn.deserialize(blob)
        conn.execute('PRAGMA trusted_schema=OFF')
        conn.execute('PRAGMA query_only=ON')
        if probe_connection(conn).version not in (1, 2):
            raise ValueError('invalid_snapshot_schema')
        yield conn


def snapshot_matches(blob, expected, kek, dek):
    with deserialize_snapshot(blob) as conn:
        return validate_records(conn, kek, dek) == expected


# ---------- 恢复事务工具（US2 T030） ----------


def clear_all_records(conn):
    """全量逻辑替换第一步：清空白名单表；不 drop 表、不执行包内 SQL。"""
    if not conn.in_transaction:
        raise ValueError('transaction_required')
    for table in ('assets', 'fields', 'approvals', 'categories', 'meta'):
        conn.execute(f'DELETE FROM {table}')
    if _has_table(conn, 'sqlite_sequence'):
        conn.execute('DELETE FROM sqlite_sequence')


def _has_table(conn, name):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (name,)).fetchone() is not None


def copy_snapshot_records(conn, snapshot):
    """从解密快照逐表参数化复制全部允许记录（含 meta 与 sqlite_sequence）。"""
    if not conn.in_transaction:
        raise ValueError('transaction_required')
    with deserialize_snapshot(snapshot) as source:
        for table in ('meta', 'categories', 'assets', 'fields', 'approvals'):
            rows = [tuple(r) for r in source.execute(f'SELECT * FROM {table}')]
            if not rows:
                continue
            columns = [d[0] for d in source.execute(f'SELECT * FROM {table} LIMIT 0').description]
            placeholders = ','.join('?' * len(columns))
            conn.executemany(f'INSERT INTO {table} ({",".join(columns)}) VALUES ({placeholders})', rows)
        if not _has_table(conn, 'sqlite_sequence') and \
                source.execute('SELECT COUNT(*) FROM sqlite_sequence').fetchone()[0]:
            # AUTOINCREMENT 首次插入才会生成该内部表；用一次受控种子行触发
            conn.execute("INSERT INTO assets (id,name) VALUES (1,'__sequence_seed__')")
            conn.execute('DELETE FROM assets')
            conn.execute('DELETE FROM sqlite_sequence')
        seq_rows = [tuple(r) for r in source.execute('SELECT name,seq FROM sqlite_sequence')]
        if seq_rows:
            # 业务行插入已让 sqlite_sequence 自动生成同名条目；先清空再写入源序号
            if _has_table(conn, 'sqlite_sequence'):
                conn.execute('DELETE FROM sqlite_sequence')
            conn.executemany('INSERT INTO sqlite_sequence (name,seq) VALUES (?,?)', seq_rows)


def restore_records_match(actual, expected):
    """逐表精确比较；仅允许两项运行态差异：
    - restore_epoch：恢复提交时重新生成的新代次；
    - maintenance_failure：旧环境维护标记不随包迁移到恢复结果。
    其余 meta/记录/序号任何差异都算失败。只输出布尔结论。
    """
    if set(actual) != set(expected):
        return False
    allowed = {'restore_epoch', 'maintenance_failure'}
    for table, rows in expected.items():
        actual_rows = actual.get(table)
        if table == 'meta':
            expected_meta = {k: v for k, v in rows if k not in allowed}
            actual_meta = {k: v for k, v in (actual_rows or []) if k not in allowed}
            if expected_meta != actual_meta:
                return False
        elif actual_rows != rows:
            return False
    return True
