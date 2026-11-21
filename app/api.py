"""REST API 蓝图：解锁、资产 CRUD、分类、搜索、AI 审批、备份、令牌。"""

import hmac
import io
from pathlib import Path

from flask import Blueprint, abort, jsonify, request, send_file, current_app, g
from werkzeug.exceptions import HTTPException

from app import crypto, db, operations, migration, maintenance as data_maintenance, settings_store
from app.backup import BackupError, MAX_PACKAGE_BYTES

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.before_request
def _request_boundary():
    manager = current_app.extensions['vault_operations']
    manager.lock.acquire()
    g.vault_request_lock = manager
    # A Flask application stays bound to its originally claimed path.
    if manager.path != db.DB_PATH.resolve():
        raise operations.OperationError('vault_context_mismatch', 503)
    origin = request.headers.get('Origin')
    same_origin = request.scheme + '://' + request.host
    if same_origin not in current_app.config['VAULT_ALLOWED_ORIGINS']:
        abort(403)
    native_ai = request.path == '/api/ai/request' and request.method == 'POST'
    write = request.method not in ('GET', 'HEAD', 'OPTIONS')
    if origin is not None and origin != same_origin:
        abort(403)
    if (write and not native_ai or request.path == '/api/vault/restore-credential') and origin != same_origin:
        abort(403)
    if request.content_length is not None and request.content_length > current_app.config['MAX_CONTENT_LENGTH']:
        abort(413)
    if native_ai and not request.is_json:
        abort(400)
    if request.path == '/api/unlock' or request.path.startswith(('/api/backup/', '/api/migration/')) \
            or request.path in ('/api/vault/restore-credential', '/api/maintenance/wipe-data'):
        manager.limit('maintenance')
    probe = db.probe_format()
    # 恢复入口自行处理空环境（missing/uninitialized）与维护状态下的显式恢复
    restore_routes = ('/api/backup/restore/prepare', '/api/backup/restore/commit')
    # US3 迁移入口允许在 legacy_read_only 下 POST：端点自行鉴权并只写配置副本，
    # 绝不由此推断允许修改活动旧库（正式切换需另行授权）
    migration_routes = ('/api/migration/prepare', '/api/migration/commit',
                        '/api/migration/backup/retry',
                        '/api/migration/rollback/prepare',
                        '/api/backup/legacy/convert')
    # restore-credential 只发放一次性凭证、不改库；空环境下需允许 POST 领取
    if write and request.path not in ('/api/unlock', '/api/lock', '/api/vault/restore-credential') \
            + restore_routes + migration_routes:
        if probe.state == 'maintenance_failed':
            raise operations.OperationError('maintenance_unavailable', 503, True)
        if probe.state != 'ready_locked':
            raise operations.OperationError('vault_read_only', 409)
    # US4：AI/审批/令牌是格式2专属域；旧库只读会话下读也拒绝（写已被上面的门拒绝）
    if probe.state == 'legacy_read_only' and \
            request.path.startswith(('/api/ai/', '/api/approvals', '/api/token')):
        raise operations.OperationError('vault_read_only', 409, False)


@bp.teardown_request
def _release_request_boundary(error):
    manager = g.pop('vault_request_lock', None)
    if manager is not None:
        manager.lock.release()


@bp.get('/vault/state')
def vault_state():
    probe = db.probe_format()
    state = probe.state
    if state == 'ready_locked':
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer ') and db.get_session(auth[7:].strip()):
            state = 'ready_unlocked'
    return jsonify({'state': state, 'schema_version': probe.version,
                    'can_initialize': state in ('missing', 'uninitialized')})


@bp.route('/vault/restore-credential', methods=['GET', 'POST'])
def restore_credential():
    # 浏览器对同源 GET 请求不一定携带 Origin；POST 一定携带，前端经 POST 领取凭证
    if db.probe_format().state not in ('missing', 'uninitialized'):
        raise operations.OperationError('restore_credential_not_allowed', 409)
    ticket = current_app.extensions['vault_operations'].issue_restore_ticket(request.headers['Origin'])
    response = jsonify({'restore_credential': ticket, 'expires_in': 300})
    response.headers['Cache-Control'] = 'no-store'
    return response


def _restore_identity():
    """Later restore routes consume this credential; it never becomes a session."""
    if db.probe_format().state in ('missing', 'uninitialized'):
        current_app.extensions['vault_operations'].consume_restore_ticket(
            request.headers.get('X-Restore-Credential', ''), request.headers.get('Origin'))
        return None
    return _session()


def _json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description="请求体必须是 JSON 对象")
    return data


def _session() -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, description="未解锁：请先调用 POST /api/unlock 获取 token")
    token = auth[7:].strip()
    sess = db.get_session(token)
    if not sess:
        abort(401, description="会话无效或已过期，请重新解锁")
    # 已授权用户操作续期闲置计时（AI 路径不经过 _session，不续期）
    db.touch_session(token)
    return sess


def _mask_asset(asset: dict) -> dict:
    asset = dict(asset)
    asset["fields"] = [
        {**dict(f), "value": db.MASK} if f["sensitive"] else dict(f)
        for f in asset["fields"]
    ]
    return asset


def _mask_payload(payload):
    """把审批 payload 中敏感字段值替换为掩码（列表展示用）。"""
    if isinstance(payload, dict):
        if payload.get("sensitive") and "value" in payload:
            out = dict(payload)
            out["value"] = db.MASK
            return out
        return {k: _mask_payload(v) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_mask_payload(v) for v in payload]
    return payload


def _change_envelope(body):
    """持久化改变成功时附加 persistence/backup 双结果；不得用 500 引导重做已成功业务。"""
    info = operations.for_vault(db.DB_PATH).pop_change_info()
    if not info:
        return body
    body = dict(body)
    body['persistence'] = {'saved': info['saved'], 'change_seq': info['change_seq']}
    body['backup'] = info['backup']
    return body


# ---------- 解锁 / 锁定 ----------


@bp.post("/unlock")
def unlock():
    data = _json_body()
    password = data.get("password")
    if not isinstance(password, str) or not password:
        abort(400, description="password 不能为空")
    try:
        token, first_run = db.unlock(password, initialize=data.get('initialize') is True)
    except ValueError:
        abort(401, description="主密码错误")
    body = _change_envelope({"token": token, "first_run": first_run})
    reconcile = operations.for_vault(db.DB_PATH).last_reconcile
    if reconcile:
        body['backup_reconciled'] = {'catch_up': reconcile.get('catch_up', False),
                                     'backup': reconcile.get('backup')}
    return jsonify(body)


@bp.post("/lock")
def lock():
    # 用户锁定使全部会话失效：换代并清空内存会话，而不只是删调用者自己的
    current_app.extensions['vault_operations'].lock_all()
    return jsonify({"ok": True})


@bp.post("/vault/password/change")
def change_vault_password():
    """修改主密码（FR-012～014）：DEK 不动重包 KEK，成功即服务端自锁。

    错误码严格按 desktop-runtime 契约：401 旧密码错误 → 400 规则违规 →
    400 两次不一致 → 503 前置备份阻断；日志与错误体不含任何密码/密钥材料。
    本端点无限频要求，不接入维护限频。
    """
    _session()  # 有效解锁会话；无会话/失效会话统一 401
    manager = current_app.extensions['vault_operations']
    # 契约：锁定/重启未解锁返 423；正常流程会话校验已先拦截，此为纵深防御
    if manager.unlock_vault_id is None:
        raise operations.OperationError('vault_locked', 423, True)
    data = _json_body()
    result = manager.change_password(
        current_password=data.get("current_password"),
        new_password=data.get("new_password"),
        confirm_password=data.get("confirm_password"))
    return jsonify(result)


# ---------- 资产 ----------


@bp.get("/assets")
def list_assets():
    sess = _session()
    assets = db.list_assets(sess["dek"])
    return jsonify([_mask_asset(a) for a in assets])


@bp.post("/assets")
def create_asset():
    sess = _session()
    data = _json_body()
    try:
        asset_id = db.create_asset(sess["dek"], data, kek=sess["kek"])
    except ValueError as e:
        abort(400, description=str(e))
    return jsonify(_change_envelope(db.get_asset(asset_id, sess["dek"]))), 201


@bp.get("/assets/<int:asset_id>")
def get_asset(asset_id):
    sess = _session()
    asset = db.get_asset(asset_id, sess["dek"])
    if not asset:
        abort(404, description="资产不存在")
    return jsonify(asset)


@bp.put("/assets/<int:asset_id>")
def update_asset(asset_id):
    sess = _session()
    data = _json_body()
    try:
        asset = db.update_asset(asset_id, sess["dek"], data, kek=sess["kek"])
    except ValueError as e:
        abort(400, description=str(e))
    if not asset:
        abort(404, description="资产不存在")
    return jsonify(_change_envelope(asset))


@bp.delete("/assets/<int:asset_id>")
def delete_asset(asset_id):
    sess = _session()
    if not db.delete_asset(asset_id, kek=sess["kek"]):
        abort(404, description="资产不存在")
    return jsonify(_change_envelope({"ok": True}))


# ---------- 分类 ----------


@bp.get("/categories")
def list_categories():
    _session()
    return jsonify(db.list_categories())


@bp.post("/categories")
def create_category():
    sess = _session()
    data = _json_body()
    try:
        db.create_category(
            data.get("key"),
            data.get("name"),
            data.get("icon"),
            data.get("sort_order"),
            kek=sess["kek"],
        )
    except db.CategoryExistsError:
        abort(409, description="分类 key 已存在")
    except ValueError as e:
        abort(400, description=str(e))
    return jsonify(_change_envelope({"ok": True})), 201


@bp.put("/categories/<key>")
def update_category(key):
    sess = _session()
    data = _json_body()
    try:
        changed = db.update_category(
            key, data.get("name"), data.get("icon"), data.get("sort_order"),
            kek=sess["kek"],
        )
    except ValueError as e:
        abort(400, description=str(e))
    if not changed:
        abort(404, description="分类不存在")
    return jsonify(_change_envelope(db.get_category(key)))


@bp.delete("/categories/<key>")
def delete_category(key):
    sess = _session()
    if not db.delete_category(key, kek=sess["kek"]):
        abort(404, description="分类不存在")
    return jsonify(_change_envelope({"ok": True}))


# ---------- 搜索 ----------


@bp.get("/search")
def search():
    sess = _session()
    q = request.args.get("q", "")
    assets = db.search(q, sess["dek"])
    return jsonify([_mask_asset(a) for a in assets])


# ---------- 本机设置（US4：AI 总开关与上云提示偏好） ----------


@bp.get("/settings")
def get_settings():
    """读取本机非敏感设置；文件缺失回安全默认且不写盘，不回显任何密钥/令牌。"""
    _session()
    settings = settings_store.load_settings()
    return jsonify({"ai_enabled": settings["ai_enabled"],
                    "ai_risk_prompt_suppressed": settings["ai_risk_prompt_suppressed"]})


@bp.put("/settings/ai-enabled")
def update_ai_enabled():
    """AI 总开关状态机：开启须显式风险确认（或已选「不再提示」），关闭免确认。"""
    _session()
    data = _json_body()
    enabled = data.get("enabled")
    confirm_risk = data.get("confirm_risk")
    if not isinstance(enabled, bool) or \
            (confirm_risk is not None and not isinstance(confirm_risk, bool)):
        abort(400, description="enabled 必须为布尔值，confirm_risk 须为布尔或省略")
    try:
        if enabled:
            current = settings_store.load_settings()
            # 409 在任何写入之前判定：未确认且无「不再提示」偏好时开关绝不落盘
            if not current["ai_risk_prompt_suppressed"] and confirm_risk is not True:
                raise operations.OperationError('risk_confirmation_required', 409, False)
            result = settings_store.set_ai_enabled(True)
        else:
            # 关闭是即时本地操作，不需要二次确认，也不触碰令牌与审批历史
            result = settings_store.set_ai_enabled(False)
    except settings_store.SettingsError:
        raise operations.OperationError('settings_persistence_failed', 503, True) from None
    return jsonify({"ai_enabled": result["ai_enabled"],
                    "ai_risk_prompt_suppressed": result["ai_risk_prompt_suppressed"]})


@bp.put("/settings/ai-risk-prompt")
def update_ai_risk_prompt():
    """「不再提示」偏好独立存取，与开关状态互不派生。"""
    _session()
    data = _json_body()
    suppress = data.get("suppress")
    if not isinstance(suppress, bool):
        abort(400, description="suppress 必须为布尔值")
    try:
        result = settings_store.set_risk_prompt_suppressed(suppress)
    except settings_store.SettingsError:
        raise operations.OperationError('settings_persistence_failed', 503, True) from None
    return jsonify({"ai_enabled": result["ai_enabled"],
                    "ai_risk_prompt_suppressed": result["ai_risk_prompt_suppressed"]})


# ---------- AI 审批 ----------


@bp.post("/ai/request")
def ai_request():
    # FR-015 开关闸门先于令牌身份与锁定三态：关闭一律 403 ai_disabled，
    # 不写审批、不进队列、不改资产、不触发备份；本闸门只前置不替换下方既有规则。
    if not settings_store.is_ai_enabled():
        raise operations.OperationError('ai_disabled', 403, False)
    # 先恒定时间验证令牌（只读摘要，不做 KDF/解密），再在操作锁内复查有效解锁：
    # 主密码/KEK/DEK 始终不进 AI 流程；锁定/重启未解锁/闲置过期一律 423 且零写入。
    presented = request.headers.get("X-AI-Token", "")
    stored = db.get_ai_token_hash() or "0" * 64
    if not hmac.compare_digest(stored, crypto.token_digest(presented)):
        abort(401, description="X-AI-Token 无效")
    ctx = current_app.extensions['vault_operations'].unlocked_context()
    if ctx is None:
        raise operations.OperationError('vault_locked', 423, True)
    data = _json_body()
    op_type = data.get("op_type")
    payload = data.get("payload")
    if op_type not in ("create", "update", "delete"):
        abort(400, description="op_type 必须是 create/update/delete")
    if not isinstance(payload, dict):
        abort(400, description="payload 必须是 JSON 对象")
    if op_type == "create" and not str(payload.get("name") or "").strip():
        abort(400, description="create 需要 payload.name")
    if op_type in ("update", "delete") and payload.get("id") is None:
        abort(400, description="update/delete 需要 payload.id")
    # AI 不续期用户闲置；使用会话 DEK 的审批用途密钥加密落盘，不直接写资产
    approval_id = db.create_ai_approval(op_type, payload,
                                        kek=ctx["kek"], dek=ctx["dek"])
    return jsonify(_change_envelope({"id": approval_id, "status": "pending"})), 201


@bp.get("/approvals")
def list_approvals():
    sess = _session()
    approvals = db.list_approvals(sess["dek"])
    for a in approvals:
        a["payload"] = _mask_payload(a["payload"])
    return jsonify(approvals)


@bp.get("/approvals/history")
def approval_history():
    """已处理审批的非敏感审计记录（不含任何提交内容，payload 处理时已清空）。"""
    _session()
    try:
        limit = min(max(int(request.args.get("limit", 30)), 1), 100)
    except (TypeError, ValueError):
        limit = 30
    return jsonify(db.list_approval_history(limit=limit))


@bp.post("/approvals/<int:approval_id>/approve")
def approve(approval_id):
    sess = _session()  # 批准需要用户已解锁（拿到 DEK 才能解开 payload 并写资产）
    try:
        asset_id = db.process_approval(
            approval_id, 'approved', dek=sess["dek"], kek=sess["kek"])
    except ValueError as e:
        abort(400, description=str(e))
    return jsonify(_change_envelope({"ok": True, "asset_id": asset_id}))


@bp.post("/approvals/<int:approval_id>/reject")
def reject(approval_id):
    sess = _session()
    db.process_approval(approval_id, 'rejected', dek=sess["dek"], kek=sess["kek"])
    return jsonify(_change_envelope({"ok": True}))


# ---------- 备份（US2 T031/T032） ----------


@bp.get("/backup/export")
def export_backup():
    sess = _session()
    manager = current_app.extensions['vault_operations']
    blob, header, managed = manager.export_package(sess["kek"], sess["dek"])
    stamp = header['captured_at'][:19].replace('-', '').replace(':', '').replace('T', '-')
    response = send_file(
        io.BytesIO(blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"vault-backup-{stamp}-{header['backup_id'][:8]}.avbak",
    )
    response.headers['X-Vault-Managed-Copy'] = managed['managed_copy']
    return response


@bp.get("/backup/status")
def backup_status():
    """锁定时仅返回是否需解锁与通用状态；不给资产信息。"""
    auth = request.headers.get("Authorization", "")
    sess = db.get_session(auth[7:].strip()) if auth.startswith("Bearer ") else None
    manager = current_app.extensions['vault_operations']
    keys = (sess["kek"], sess["dek"]) if sess else None
    return jsonify(manager.backup_status(keys=keys))


@bp.get("/backup/history")
def backup_history():
    """受管备份包清单（非敏感头部信息）：序号/时间/用途/是否当前代次。"""
    _session()
    try:
        limit = min(max(int(request.args.get("limit", 30)), 1), 100)
    except (TypeError, ValueError):
        limit = 30
    return jsonify({"items": current_app.extensions['vault_operations']
                    .backup_history(limit=limit)})


@bp.get("/backup/history/<backup_id>/export")
def export_history_backup(backup_id):
    """下载受管目录中的历史加密备份包；打开仍需该包当时的主密码。"""
    _session()
    blob, header = current_app.extensions['vault_operations'] \
        .export_history_package(backup_id)
    stamp = header['captured_at'][:19].replace('-', '').replace(':', '').replace('T', '-')
    response = send_file(
        io.BytesIO(blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"vault-backup-{stamp}-{header['backup_id'][:8]}.avbak",
    )
    response.headers['X-Vault-Managed-Copy'] = 'history'
    return response


@bp.post("/backup/retry")
def backup_retry():
    """只重试备份：不重做业务、不增 change_seq；失败保留旧有效包。"""
    sess = _session()
    manager = current_app.extensions['vault_operations']
    result = manager.retry_backup(sess["kek"], sess["dek"])
    return jsonify({'backup': result})


@bp.post("/backup/restore/prepare")
def backup_restore_prepare():
    """multipart file + backup_password；包只在内存验真。"""
    identity = _restore_identity()
    file = request.files.get("file")
    password = request.form.get("backup_password")
    if not file:
        abort(400, description="请上传 file 字段（.avbak 备份文件）")
    blob = file.read(MAX_PACKAGE_BYTES + 1)
    if not blob:
        abort(400, description="备份文件为空")
    if not isinstance(password, str) or not password:
        abort(400, description="backup_password 不能为空")
    manager = current_app.extensions['vault_operations']
    try:
        result = manager.prepare_restore(blob, password,
                                         origin=request.headers['Origin'],
                                         session=identity)
    finally:
        del blob  # 备份密码与包字节只在内存，不写 URL/日志/localStorage
    return jsonify(result)


@bp.post("/backup/restore/commit")
def backup_restore_commit():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form.to_dict()
    manager = current_app.extensions['vault_operations']
    # 空环境恢复无用户会话；已有库须有效用户会话（prepare/commit 权限分离）
    if db.probe_format().state in ('missing', 'uninitialized'):
        identity = None
    else:
        identity = _session()
    result = manager.commit_restore(
        str(data.get('operation_id') or ''),
        confirmation_nonce=str(data.get('confirmation_nonce') or ''),
        confirm_replace=data.get('confirm_replace') is True or data.get('confirm_replace') == 'true',
        session=identity,
        origin=request.headers.get('Origin'))
    return jsonify(result)


@bp.post("/backup/import")
def import_backup():
    """旧入口兼容：不再直接覆盖，引导到 prepare/confirm 流程。"""
    _session()
    raise operations.OperationError('confirmation_required', 409)


# ---------- 旧库副本升级与旧材料转换（US3） ----------


def _configured_source(source_id):
    """迁移目标只能来自安全环境配置白名单；请求体不决定任意源路径。"""
    configured = current_app.config.get('VAULT_MIGRATION_SOURCES') or {}
    raw = configured.get(source_id)
    if not isinstance(raw, str) or not raw:
        raise operations.OperationError('migration_source_not_configured', 404)
    path = Path(raw).resolve()
    if path == Path(db.DB_PATH).resolve():
        # 日常活动库不得作为副本升级目标：不自动正式切换
        raise operations.OperationError('migration_source_is_active', 409)
    return path


@bp.get("/migration/sources")
def migration_sources():
    """列举安全环境配置的可升级副本；只给非敏感状态，不暴露服务器路径。"""
    _session()
    result = []
    for source_id, raw in (current_app.config.get('VAULT_MIGRATION_SOURCES') or {}).items():
        if not isinstance(raw, str) or not raw:
            continue
        probe = db.probe_format(Path(raw))
        result.append({"id": source_id, "state": probe.state,
                       "schema_version": probe.version})
    return jsonify(result)


@bp.post("/migration/prepare")
def migration_prepare():
    """用主密码在只读连接上解锁配置副本；协调器内存预演并发前置保全包。"""
    _session()
    data = _json_body()
    source_id, password = data.get("source"), data.get("password")
    if not isinstance(source_id, str) or not source_id:
        abort(400, description="source 不能为空")
    if not isinstance(password, str) or not password:
        abort(400, description="password 不能为空")
    source = _configured_source(source_id)
    with db.connection(source, readonly=True) as conn:
        probe = db.probe_connection(conn)
        if probe.state in ("ready_locked", "maintenance_failed"):
            raise operations.OperationError('migration_not_required', 409)
        if probe.state != "legacy_read_only":
            raise operations.OperationError('unsupported_legacy_format', 409)
        try:
            kek, dek = db.credentials(conn, password)
        except ValueError:
            raise operations.OperationError('invalid_credentials_or_corrupt', 401) from None
    return jsonify(operations.for_vault(source).prepare_migration(kek, dek))


@bp.post("/migration/commit")
def migration_commit():
    """显式确认后只升级配置副本；活动旧库字节不变、不切换日常入口。"""
    _session()
    data = _json_body()
    source = _configured_source(str(data.get("source") or ""))
    result = operations.for_vault(source).commit_migration(
        str(data.get("operation_id") or ""),
        confirmation_nonce=str(data.get("confirmation_nonce") or ""),
        confirm_upgrade=data.get("confirm_upgrade") is True)
    return jsonify(result)


@bp.post("/migration/backup/retry")
def migration_backup_retry():
    """已升级副本仅后置备份失败时补包；不重做迁移、不增序号。"""
    _session()
    data = _json_body()
    source = _configured_source(str(data.get("source") or ""))
    result = operations.for_vault(source).retry_migration_backup(
        str(data.get("operation_id") or ""))
    return jsonify(result)


@bp.post("/migration/rollback/prepare")
def migration_rollback_prepare():
    """回退前先保全当前最新状态；只核对与出包，不执行覆盖。"""
    sess = _session()
    manager = current_app.extensions['vault_operations']
    return jsonify(manager.rollback_prepare(sess["kek"], sess["dek"]))


_CONVERT_ERROR_STATUS = {
    'legacy_key_required': (409, False),
    'invalid_credentials_or_corrupt': (401, False),
    'migration_not_required': (409, False),
    'unsupported_legacy_format': (409, False),
    'legacy_convert_failed': (409, False),
    'invalid_package': (400, False),
    'invalid_request': (400, False),
}


@bp.post("/backup/legacy/convert")
def backup_legacy_convert():
    """旧 .bin（凭会话中匹配旧 DEK）或 schema1 包（凭包密码）仅内存转换为 schema2 包。"""
    sess = _session()
    uploaded = request.files.get("file")
    if uploaded is None:
        abort(400, description="请上传 file 字段（旧 .bin 或 schema1 .avbak）")
    blob = uploaded.read(MAX_PACKAGE_BYTES + 1)
    if not blob:
        abort(400, description="材料文件为空")
    password = request.form.get("backup_password")
    try:
        if blob[:len(b"AVBK0002")] == b"AVBK0002":
            if not isinstance(password, str) or not password:
                abort(400, description="schema1 备份包转换必须提供 backup_password")
            out_blob, header = migration.convert_schema1_package(blob, password=password)
        else:
            # 旧 .bin 的解密材料是旧 DEK，不是主密码本身
            out_blob, header = migration.convert_legacy_bin(
                blob, kek=sess["kek"], dek=sess["dek"])
    except ValueError as exc:
        status, retryable = _CONVERT_ERROR_STATUS.get(str(exc), (400, False))
        raise operations.OperationError(str(exc), status, retryable) from None
    finally:
        del blob  # 解密材料与包字节只在请求内存中
    stamp = header['captured_at'][:19].replace('-', '').replace(':', '').replace('T', '-')
    response = send_file(
        io.BytesIO(out_blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"vault-migrated-{stamp}-{header['backup_id'][:8]}.avbak",
    )
    response.headers['Cache-Control'] = 'no-store'
    return response


# ---------- 维护：删除全部数据（T031，FR-004） ----------

# MaintenanceError 稳定机器码到 HTTP 状态的映射；与 CLI 退出码是同一契约的两种表达
_WIPE_ERROR_STATUS = {
    'data_dir_missing': (409, False),
    'vault_not_found': (409, False),
    'wipe_failed': (503, True),
}


@bp.post("/maintenance/wipe-data")
def maintenance_wipe_data():
    """删除全部数据的 HTTP 等价路径：双确认任一不满足即 409 且磁盘零变化。

    运行中的桌面进程已由共享 manager 持有进程字节锁，故走进程内核心
    wipe_data_contents，不抢锁、不碰锁文件；成功后全部内存会话立即作废，
    前端回到首启两入口状态。绕过确认（含直接调 API）的成功率为零。
    """
    _session()  # 危险操作要求有效解锁会话；无会话 401，不进入任何文件操作
    data = _json_body()
    acknowledged = data.get("acknowledge_risk") is True
    confirmed_text = str(data.get("confirm_text") or "").strip() == "DELETE"
    if not (acknowledged and confirmed_text):
        raise operations.OperationError('wipe_confirmation_required', 409, False)
    try:
        data_maintenance.wipe_data_contents(db.DB_PATH.parent)
    except data_maintenance.MaintenanceError as exc:
        status, retryable = _WIPE_ERROR_STATUS.get(exc.code, (503, True))
        raise operations.OperationError(exc.code, status, retryable) from None
    # 库已删除：换代并清空全部内存会话，旧 token 立刻失效
    current_app.extensions['vault_operations'].lock_all()
    return jsonify({"ok": True, "status": "wiped"})


# ---------- AI 令牌 ----------


@bp.get("/token")
def get_token():
    sess = _session()
    response = jsonify({"ai_token": db.reveal_ai_token(sess["dek"])})
    response.headers['Cache-Control'] = 'no-store'
    return response


@bp.post("/token/reset")
def reset_token():
    sess = _session()
    # 同事务换摘要/密文 + 一次备份；旧 pending 由 DEK 审批密钥保护，不受影响
    token = db.reset_ai_token(dek=sess["dek"], kek=sess["kek"])
    return jsonify(_change_envelope({"ai_token": token}))


# ---------- 错误处理 ----------


@bp.errorhandler(400)
@bp.errorhandler(401)
@bp.errorhandler(403)
@bp.errorhandler(404)
@bp.errorhandler(405)
@bp.errorhandler(409)
@bp.errorhandler(413)
@bp.errorhandler(423)
@bp.errorhandler(503)
def _handle_http_error(e):
    status = e.code or 400
    codes = {400: 'invalid_request', 401: 'invalid_identity_or_credentials', 403: 'forbidden_origin_or_host',
             404: 'not_found', 405: 'method_not_allowed', 409: 'conflict', 413: 'request_too_large',
             423: 'vault_locked', 503: 'maintenance_unavailable'}
    return jsonify({'error': '请求被拒绝', 'code': codes.get(status, 'request_error'),
                    'retryable': status in (423, 503)}), status


@bp.errorhandler(operations.OperationError)
def _handle_operation_error(e):
    return jsonify({'error': '操作暂不可执行', 'code': e.code, 'retryable': e.retryable}), e.status


@bp.errorhandler(BackupError)
def _handle_backup_error(e):
    """备份包错误码到 HTTP 的映射；不泄露内部细节。"""
    mapping = {'package_too_large': (413, False),
               'invalid_package': (400, False),
               'unsupported_package': (400, False),
               'invalid_credentials_or_corrupt': (401, False),
               'target_exists': (409, False),
               'backup_permissions_failed': (503, True)}
    status, retryable = mapping.get(e.code, (400, False))
    return jsonify({'error': '备份操作失败', 'code': e.code, 'retryable': retryable}), status


@bp.errorhandler(Exception)
def _handle_unexpected(e):
    if isinstance(e, HTTPException):
        return _handle_http_error(e)
    # No exception repr/traceback: either may contain fields, passwords or payloads.
    current_app.logger.error('internal_error')
    return jsonify({'error': '服务器内部错误', 'code': 'internal_error', 'retryable': False}), 500
