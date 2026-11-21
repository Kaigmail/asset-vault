"""共享连接生命周期、操作屏障、Windows 单活动库租约与 Spec-001 US2 协调。

协调职责（T027–T030）：
- 一次业务事务/change_seq → 内存快照 → 自动备份，全程写锁串行化；
- 提交后备份失败返回 saved=true 不回滚新数据；真实数据异常才冻结；
- 恢复 prepare 内存验真、5 分钟确认生命周期、绑定包摘要与目标三元组；
- 恢复 commit 屏障内单事务全量逻辑替换/空库恢复，恢复后代次换代。
Foundation 部分不变：同一重入锁串行化该库全部操作。
"""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
import uuid

from app import backup as backup_module
from app import migration as migration_mod
from app.backup import BackupError, BackupStore

RESTORE_TTL = 300          # 5 分钟确认有效期
RESTORE_MAX_OPS = 4
MIGRATION_MAX_OPS = 4
IDLE_TTL = 15 * 60         # 用户会话默认闲置 15 分钟失效（AI 请求不续期）

# 改密成功后给前端的固定提示：历史备份包的密码不随改密改写
HISTORICAL_BACKUP_NOTE = "历史备份仍使用导出时的旧密码，不会被改写"
# 主密码唯一规则：恰好 6 位 ASCII 数字（不引入其他强度规则）
PASSWORD_RULE = re.compile(r"[0-9]{6}")


class OperationError(RuntimeError):
    def __init__(self, code, status=409, retryable=False):
        super().__init__(code)
        self.code, self.status, self.retryable = code, status, retryable


class ChangeFrame:
    """一次业务事务的变更框架；无 mark 即无序号、无备份。"""
    __slots__ = ("seq",)

    def __init__(self):
        self.seq = None


def _restore_contents(records):
    """从已验证快照记录提取非敏感计数，供恢复核验页显示「备份里有什么」。

    records 为 db.logical_records 原始行（approvals 为 SELECT * 元组，
    列序 id/op_type/payload/status/...，status 固定在索引 3）；只回整数。
    """
    approvals = records.get('approvals', ()) if records else ()
    return {
        'asset_count': len(records.get('assets', ())) if records else 0,
        'field_count': len(records.get('fields', ())) if records else 0,
        'category_count': len(records.get('categories', ())) if records else 0,
        'pending_count': sum(1 for row in approvals if len(row) > 3 and row[3] == 'pending'),
    }


class RestoreOperation:
    """仅内存的恢复操作；5 分钟过期释放，不写 URL/日志/localStorage。"""
    __slots__ = ("kind", "snapshot", "kek", "dek", "header", "digest", "records",
                 "confirmation_nonce", "expires_at", "origin", "bound", "pre_backup",
                 "status")

    def __init__(self, kind, *, snapshot, kek, dek, header, digest, records, origin):
        self.kind = kind                  # 'empty' 或 'replace'
        self.snapshot = snapshot
        self.kek, self.dek = kek, dek
        self.header = header
        self.digest = digest
        self.records = records
        self.confirmation_nonce = secrets.token_urlsafe(32)
        self.expires_at = time.monotonic() + RESTORE_TTL
        self.origin = origin
        self.bound = None                 # (vault_id, restore_epoch, change_seq)
        self.pre_backup = None
        self.status = 'prepared'


class VaultOperations:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.lock = threading.RLock()
        self.maintenance = False
        self.connections = set()
        self._lease = None
        self._tickets = {}
        self._rates = {}
        self._backups = None
        self.change_info = None           # 最近一次业务变更的双结果
        self.last_reconcile = None        # 最近一次解锁补备份结论
        self._restores = {}
        self._migrations = {}             # 绑定本管理器路径（迁移副本）的待确认操作
        # 确定性故障/暂停钩子：仅受控测试子进程注入（before_backup/written/
        # verified/published 节点）；生产代码路径恒为 None
        self.backup_fault = None
        # 改密事务故障钩子：仅受控测试注入（password_change_before/after_commit）
        self.password_change_fault = None
        # US4 仅内存解锁状态：代次/库身份随解锁登记，锁定或恢复换代；
        # 重启后进程内存天然无登记，等效全锁
        self.unlock_generation = 0
        self.unlock_vault_id = None
        self.idle_ttl = IDLE_TTL

    # ---------- 内存解锁状态（US4 T050） ----------

    def register_unlock(self, vault_id):
        """用户成功解锁后登记当前库身份并返回当代代次；不改变代次。"""
        with self.lock:
            self.unlock_vault_id = vault_id
            return self.unlock_generation

    def lock_all(self):
        """显式锁定：换代、清库身份并清空全部内存会话（不止调用者自己）。"""
        from app import db
        with self.lock:
            self.unlock_generation += 1
            self.unlock_vault_id = None
            db.SESSIONS.clear()

    def _session_alive(self, sess, now):
        return sess.get('vault_path') == str(self.path) \
            and sess.get('generation') == self.unlock_generation \
            and sess.get('vault_id') == self.unlock_vault_id \
            and now - sess.get('last_activity', 0.0) <= self.idle_ttl

    def context_valid(self, sess):
        """校验单个用户会话：路径/代次/库身份/闲置过期；不更新活动时间。"""
        with self.lock:
            return self._session_alive(sess, time.monotonic())

    def unlocked_context(self):
        """AI 提交在操作锁内复查：有有效未过期用户会话才返回其密钥上下文。

        取最近活动的一个会话；绝不由此延长闲置时间（AI 不续期）。
        """
        from app import db
        with self.lock:
            now = time.monotonic()
            alive = [sess for sess in db.sessions_for_path(self.path)
                     if self._session_alive(sess, now)]
            return max(alive, key=lambda s: s['last_activity'], default=None)

    # ---------- 基础屏障 ----------

    @contextmanager
    def barrier(self, *, maintenance=False):
        with self.lock:
            if self.maintenance and not maintenance:
                raise OperationError('maintenance_unavailable', 503, True)
            old = self.maintenance
            if maintenance:
                self.maintenance = True
            try:
                yield self
            finally:
                self.maintenance = old

    def claim_process(self):
        """Hold a byte-range lock for the application lifetime, never lock the DB itself."""
        with self.lock:
            if self._lease is not None:
                raise OperationError('vault_in_use', 423, True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            stream = self.path.with_suffix(self.path.suffix + '.lck').open('a+b')
            try:
                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b'\0'); stream.flush()
                stream.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                stream.close()
                raise OperationError('vault_in_use', 423, True) from None
            self._lease = stream

    def close(self):
        with self.lock:
            if self.connections:
                raise OperationError('connections_still_open', 503, True)
            self._tickets.clear()
            self._restores.clear()
            self._migrations.clear()
            # 注销单例：之后 for_vault 等效于进程重启，须从磁盘状态重新识别
            with _REGISTRY_LOCK:
                key = str(self.path.resolve()).casefold()
                if _REGISTRY.get(key) is self:
                    del _REGISTRY[key]
            if self._lease is not None:
                stream, self._lease = self._lease, None
                stream.seek(0)
                try:
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                finally:
                    stream.close()

    def limit(self, identity, limit=20, period=60):
        with self.lock:
            now = time.monotonic()
            entries = [t for t in self._rates.get(identity, ()) if now - t < period]
            if len(entries) >= limit:
                raise OperationError('maintenance_rate_limited', 503, True)
            self._rates[identity] = entries + [now]

    def issue_restore_ticket(self, origin):
        with self.lock:
            now = time.monotonic()
            self._tickets = {k: v for k, v in self._tickets.items() if v[1] > now}
            if len(self._tickets) >= 20:
                raise OperationError('maintenance_rate_limited', 503, True)
            ticket = secrets.token_urlsafe(32)
            self._tickets[ticket] = (origin, now + 300)
            return ticket

    def consume_restore_ticket(self, ticket, origin):
        with self.lock:
            value = self._tickets.pop(ticket, None)
            if value is None or value[0] != origin or value[1] <= time.monotonic():
                raise OperationError('invalid_restore_credential', 401)

    # ---------- 备份协调（T027/T028） ----------

    def backup_store(self):
        if self._backups is None:
            self._backups = BackupStore(self.path.parent / 'backups')
        return self._backups

    def finalize_change(self, kek, seq):
        """业务事务提交后：内存快照→自动备份→清单。失败保留数据与旧有效包。"""
        from app import db
        fault = self.backup_fault  # 受控测试钩子；生产恒为 None
        try:
            if not isinstance(kek, bytes) or len(kek) != 32:
                raise BackupError('backup_key_required')
            if fault is not None:
                fault('before_backup')  # 业务事务已提交、备份尚未开始
            snapshot = db.snapshot_bytes(self.path)
            result = self.backup_store().create(snapshot, kek=kek, fault=fault)
            return {'saved': True, 'change_seq': seq, 'backup': result}
        except BackupError as exc:
            return {'saved': True, 'change_seq': seq,
                    'backup': {'status': 'failed', 'backup_id': None,
                               'error_code': exc.code, 'retry_available': True}}
        except Exception:
            return {'saved': True, 'change_seq': seq,
                    'backup': {'status': 'failed', 'backup_id': None,
                               'error_code': 'backup_failed', 'retry_available': True}}

    def pop_change_info(self):
        info, self.change_info = self.change_info, None
        return info

    def current_identity(self):
        """只读读取当前库身份三元组；空/缺失库返回 None。"""
        from app import db
        probe = db.probe_format(self.path)
        if probe.state not in ('ready_locked', 'maintenance_failed'):
            return None
        with db.connection(self.path, readonly=True) as conn:
            meta = db.meta_values(conn)
        return {'vault_id': meta['vault_id'], 'restore_epoch': meta['restore_epoch'],
                'change_seq': int(meta['change_seq'])}

    def reconcile_backups(self, kek, dek):
        """下次正确解锁补备份：清单/包按三元组精确核对；未解锁前不后台生成。"""
        from app import db
        try:
            identity = self.current_identity()
            if identity is None:
                self.last_reconcile = None
                return None
            store = self.backup_store()
            store.cleanup_temps()
            status = store.status_for(identity['vault_id'], identity['restore_epoch'],
                                      identity['change_seq'], kek=kek, dek=dek)
            catch_up = status['latest_verified_seq'] != identity['change_seq']
            result = None
            if catch_up:
                snapshot = db.snapshot_bytes(self.path)
                result = store.create(snapshot, kek=kek)
            self.last_reconcile = {'catch_up': catch_up, 'status': status,
                                   'backup': result}
            return self.last_reconcile
        except Exception:
            self.last_reconcile = {'catch_up': False, 'status': 'failed',
                                   'error_code': 'backup_failed'}
            return self.last_reconcile

    def export_package(self, kek, dek, *, purpose='manual'):
        """回读验证成功才导出；仅导出不增加 change_seq。"""
        from app import db
        identity = self.current_identity()
        if identity is None:
            raise OperationError('vault_not_ready', 409)
        snapshot = db.snapshot_bytes(self.path)
        with db.deserialize_snapshot(snapshot) as conn:
            records = db.validate_records(conn, kek, dek)
        identity = backup_module.snapshot_identity(snapshot)
        blob, header = backup_module.encrypt_package(
            snapshot, kek=kek, salt=identity["salt"], vault_id=identity["vault_id"],
            restore_epoch=identity["restore_epoch"], change_seq=identity["change_seq"],
            db_schema_version=identity["db_schema_version"], purpose=purpose)
        store = self.backup_store()
        if purpose == 'manual':
            try:
                store.publish_verified(blob, header, kek=kek, expected_records=records)
            except BackupError as exc:
                # 受管副本失败不阻止浏览器下载；不冒充已受管保存
                return blob, header, {'managed_copy': 'failed', 'error_code': exc.code}
            return blob, header, {'managed_copy': 'ok'}
        return blob, header, {'managed_copy': 'skipped'}

    def retry_backup(self, kek, dek):
        """备份最新已保存状态；不重做业务、不增序号；失败保留旧有效包。"""
        from app import db
        identity = self.current_identity()
        if identity is None:
            raise OperationError('vault_not_ready', 409)
        snapshot = db.snapshot_bytes(self.path)
        result = self.backup_store().create(snapshot, kek=kek)
        return result

    def backup_status(self, *, keys=None):
        """keys=(kek,dek) 时返回精确状态；锁定时仅通用信息。"""
        identity = self.current_identity()
        if identity is None:
            return {'state': 'unavailable', 'local_only': True}
        store = self.backup_store()
        if keys is None:
            return {'state': 'locked', 'local_only': True,
                    'status': 'pending', 'retry_available': False}
        status = store.status_for(identity['vault_id'], identity['restore_epoch'],
                                  identity['change_seq'], kek=keys[0], dek=keys[1])
        status['state'] = 'ready'
        return status

    def backup_history(self, *, limit=30):
        """受管备份包的非敏感清单（时间/序号/用途/是否当代次）；需已解锁身份。"""
        identity = self.current_identity()
        if identity is None:
            raise OperationError('vault_not_ready', 409)
        return self.backup_store().list_packages(
            identity['vault_id'], identity['restore_epoch'], limit=limit)

    def export_history_package(self, backup_id):
        """重新下载受管目录中的历史加密备份包（打开仍需该包当时的主密码）。"""
        identity = self.current_identity()
        if identity is None:
            raise OperationError('vault_not_ready', 409)
        located = self.backup_store().locate_package(backup_id)
        if located is None:
            raise OperationError('backup_not_found', 404)
        path, header = located
        try:
            return path.read_bytes(), header
        except OSError:
            raise OperationError('backup_not_found', 404) from None

    # ---------- 恢复（T029/T030） ----------

    def _gc_restores(self):
        now = time.monotonic()
        expired = [key for key, op in self._restores.items() if op.expires_at <= now]
        for key in expired:
            del self._restores[key]

    def prepare_restore(self, blob, password, *, origin, session=None):
        """内存验真；空环境用一次性凭证，已有目标须会话并先建已验证前置备份。"""
        from app import db
        self._gc_restores()
        if not isinstance(blob, bytes) or not blob or len(blob) > backup_module.MAX_PACKAGE_BYTES:
            raise OperationError('package_too_large', 413)
        if not isinstance(password, str) or not password:
            raise OperationError('invalid_request', 400)
        try:
            header, snapshot = backup_module.decrypt_package(blob, password)
        except BackupError as exc:
            if exc.code in ('package_too_large',):
                raise OperationError(exc.code, 413) from None
            if exc.code == 'invalid_credentials_or_corrupt':
                raise OperationError(exc.code, 401) from None
            raise OperationError(exc.code, 400) from None
        if header['db_schema_version'] != 2:
            # 格式 1 包先要求 US3 迁移能力，不可直接写为 ready
            raise OperationError('migration_required', 409)
        if header['purpose'] not in backup_module.PURPOSES:
            raise OperationError('invalid_package', 400)
        with db.deserialize_snapshot(snapshot) as conn:
            kek_r, dek_r = db.credentials(conn, password)
            records = db.validate_records(conn, kek_r, dek_r)
            meta = db.meta_values(conn)
        # 头部身份/代次/盐必须匹配快照 meta
        if header['vault_id'] != meta['vault_id'] or \
                header['restore_epoch'] != meta['restore_epoch'] or \
                header['change_seq'] != int(meta['change_seq']) or \
                not hmac.compare_digest(header['kdf']['salt'], meta['salt']):
            raise OperationError('invalid_package', 400)
        probe = db.probe_format(self.path)
        op = RestoreOperation(
            'empty' if probe.state in ('missing', 'uninitialized') else 'replace',
            snapshot=snapshot, kek=kek_r, dek=dek_r, header=header,
            digest=hashlib.sha256(blob).hexdigest(), records=records, origin=origin)
        if len(self._restores) >= RESTORE_MAX_OPS:
            raise OperationError('maintenance_rate_limited', 503, True)
        if op.kind == 'empty':
            if session is not None:
                raise OperationError('restore_credential_required', 401)
            # 一次性恢复凭证已在 API 入口消费；绑定来源与操作
        else:
            if session is None:
                raise OperationError('session_required', 401)
            if probe.state == 'maintenance_failed':
                # 异常当前库须能形成有效前置备份，否则拒绝覆盖
                pass
            self._pre_restore_backup(op, session)
        key = secrets.token_urlsafe(16)
        self._restores[key] = op
        return self._restore_view(key, op, probe)

    def _pre_restore_backup(self, op, session):
        """已有库覆盖前创建并验证当前包；失败返回 503 阻止覆盖。"""
        from app import db
        identity = self.current_identity()
        if identity is None:
            raise OperationError('vault_not_ready', 409)
        try:
            snapshot = db.snapshot_bytes(self.path)
            pre = self.backup_store().create(snapshot, kek=session['kek'],
                                             purpose='pre_restore')
        except Exception:
            pre = {'status': 'failed', 'error_code': 'pre_backup_failed'}
        if pre.get('status') != 'ok':
            raise OperationError('pre_backup_failed', 503, True)
        op.pre_backup = pre
        op.bound = (identity['vault_id'], identity['restore_epoch'],
                    identity['change_seq'])

    def _restore_view(self, key, op, probe=None):
        return {
            'contents': _restore_contents(op.records),
            'operation_id': key,
            'confirmation_nonce': op.confirmation_nonce,
            'mode': 'replace' if op.kind == 'replace' else 'initialize_restore',
            'captured_at': op.header['captured_at'],       # 认证后的捕获时间
            'change_seq': op.header['change_seq'],
            'expires_in': max(0, int(op.expires_at - time.monotonic())),
            'target_exists': op.kind == 'replace',
            'confirm_replace_required': op.kind == 'replace',
            'pre_backup': op.pre_backup,
            'warning': ('恢复将整体替换当前库，而不是合并；'
                        '恢复后需使用备份当时的主密码重新解锁') if op.kind == 'replace'
                       else '将在空环境中恢复备份内容；恢复后需用备份当时的主密码解锁',
        }

    def get_restore(self, key):
        self._gc_restores()
        return self._restores.get(key)

    def commit_restore(self, key, *, confirmation_nonce, confirm_replace=False,
                       session=None, origin=None, fault=None):
        """屏障内单事务全量逻辑替换/空库恢复；提交后代次换代、会话全部失效。"""
        from app import db
        fault = fault or (lambda node: None)
        op = self.get_restore(key)
        if op is None or op.status != 'prepared':
            raise OperationError('confirmation_stale', 409)
        if not hmac.compare_digest(op.confirmation_nonce, confirmation_nonce or ''):
            raise OperationError('invalid_confirmation', 401)
        if op.expires_at <= time.monotonic():
            self._restores.pop(key, None)
            raise OperationError('confirmation_expired', 409)
        if op.kind == 'replace':
            if session is None:
                raise OperationError('session_required', 401)
            if confirm_replace is not True:
                raise OperationError('confirmation_required', 409)
        probe_before = db.probe_format(self.path)
        if op.kind == 'replace':
            identity = self.current_identity()
            if identity is None or tuple(identity.values()) != op.bound:
                raise OperationError('stale_confirmation', 409)
        # 短时维护屏障内提交；恢复后代次重新生成
        frozen = False
        try:
            with self.barrier(maintenance=True):
                try:
                    if op.kind == 'empty':
                        self._restore_empty(op, fault)
                    else:
                        self._restore_replace(op, fault)
                except OperationError:
                    raise
                except BackupError as exc:
                    raise OperationError(exc.code, 500) from None
                except Exception:
                    raise OperationError('restore_failed', 500) from None
                fault('committed')
                # 提交后核验：从磁盘回读验证真实数据
                try:
                    snapshot = db.snapshot_bytes(self.path)
                    with db.deserialize_snapshot(snapshot) as conn:
                        disk_records = db.validate_records(conn, op.kek, op.dek)
                except Exception:
                    self._freeze_maintenance()
                    frozen = True
                    raise OperationError('committed_data_invalid', 500) from None
                if not db.restore_records_match(disk_records, op.records):
                    self._freeze_maintenance()
                    frozen = True
                    raise OperationError('committed_data_invalid', 500)
        except OperationError:
            # 失败的操作不可重复提交：提交前故障目标库未变（事务回滚），
            # 提交后核验失败已持久冻结；绝不允许异常被 finally 的返回值吞掉
            op.status = 'failed'
            op.bound = None
            raise
        finally:
            if frozen:
                # barrier 退出会复位 maintenance；冻结须在屏障外继续生效
                self.maintenance = True
        # ---- 仅成功路径：换代后的会话失效与新代次备份 ----
        op.status = 'committed'
        op.bound = None
        # 全部旧会话失效；用户以备份当时密码重新解锁
        db.SESSIONS.clear()
        self.unlock_generation += 1
        self.unlock_vault_id = None
        # 新代次必须 pending 直到新包验证；单纯后置备份失败不冻结正常数据
        backup_result = self.backup_store().create(
            db.snapshot_bytes(self.path), kek=op.kek)
        if backup_result.get('status') != 'ok':
            return {'committed': True, 'result': 'committed_backup_failed',
                    'backup': backup_result, 'revoked_sessions': True,
                    'restore_epoch': None, 'requires_reunlock': True}
        return {'committed': True, 'result': 'committed',
                'backup': backup_result, 'revoked_sessions': True,
                'restore_epoch': None, 'requires_reunlock': True}

    def _restore_replace(self, op, fault):
        """已有库：单事务参数化全量逻辑替换；事务内核验失败目标不变。"""
        from app import db
        with db.connection(self.path, readonly=False) as conn, db.transaction(conn):
            db.clear_all_records(conn)
            db.copy_snapshot_records(conn, op.snapshot)
            db.write_format2_identity(conn, vault_id=op.header['vault_id'],
                                      change_seq=op.header['change_seq'])
            fault('before_commit')
            self._verify_restored(conn, op)

    def _restore_empty(self, op, fault):
        """空环境：不先创建无关 DEK、不伪装初始化成功；失败留明确未完成标记。"""
        from app import db
        path = self.path
        marker = db.initialization_marker(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            if not marker.exists():
                with marker.open('xb') as stream:
                    stream.write(b'explicit-initialization-incomplete')
                    stream.flush()
                    os.fsync(stream.fileno())
            with path.open('xb'):
                pass
        try:
            with db.connection(path, create=True) as conn, db.transaction(conn):
                db.create_schema(conn)
                db.clear_all_records(conn)
                db.copy_snapshot_records(conn, op.snapshot)
                db.write_format2_identity(conn, vault_id=op.header['vault_id'],
                                          change_seq=op.header['change_seq'])
                fault('before_commit')
                self._verify_restored(conn, op)
        except Exception:
            raise  # 保留明确未完成标记；不清理为“已初始化”
        marker.unlink(missing_ok=True)

    def _verify_restored(self, conn, op):
        """提交前在事务内核验完整性/记录/凭证；失败回滚目标不变。"""
        from app import db
        records = db.validate_records(conn, op.kek, op.dek)
        if not db.restore_records_match(records, op.records):
            raise OperationError('restore_mismatch', 500)

    def _freeze_maintenance(self):
        """真实数据异常：持久化非敏感维护标记，冻结业务写入，重启仍有效。

        已在维护屏障内，不能再走 db._conn（其无参 barrier 会把维护态拒之门外）；
        直接用底层连接在短事务内写标记。
        """
        from app import db
        try:
            with db.connection(self.path, readonly=False) as conn, db.transaction(conn):
                conn.execute("INSERT OR REPLACE INTO meta VALUES ('maintenance_failure',"
                             " 'committed_data_invalid')")
                db._validate_meta(db.meta_values(conn), 2)
        except Exception:
            pass  # 标记写不进去时也保持内存冻结状态
        self.maintenance = True

    # ---------- 副本升级迁移（US3 T040–T044） ----------

    def _gc_migrations(self):
        now = time.monotonic()
        for key in [k for k, op in self._migrations.items() if op.expires_at <= now]:
            del self._migrations[key]

    def get_migration(self, key):
        # 不在这里 GC：提交路径需要让过期确认走到 confirmation_expired 分支；
        # 过期清理只在新建 prepare 时做
        return self._migrations.get(key)

    def prepare_migration(self, kek, dek):
        """只读核验旧副本 → 内存完整预演 → 发布 schema1 前置保全包。

        全程不写源库；预演或任一审评解密失败即拒绝；前置包失败阻止提交。
        """
        from app import db
        if not isinstance(kek, bytes) or len(kek) != 32 or \
                not isinstance(dek, bytes) or len(dek) != 32:
            raise OperationError('backup_key_required', 400)
        self._gc_migrations()
        with self.barrier(maintenance=True):
            probe = db.probe_format(self.path)
            if probe.state in ('ready_locked', 'maintenance_failed'):
                raise OperationError('migration_not_required', 409)
            if probe.state != 'legacy_read_only':
                # 未知/较新/部分初始化/损坏：明确拒绝，不静默初始化
                raise OperationError('unsupported_legacy_format', 409)
            snapshot = db.snapshot_bytes(self.path)
            digest = hashlib.sha256(snapshot).hexdigest()
            try:
                _, records_before, _, old_token = \
                    migration_mod.rehearse_upgrade(snapshot, kek, dek)
            except ValueError as exc:
                code = str(exc)
                known = ('migration_preview_failed', 'unsupported_legacy_format')
                raise OperationError(code if code in known
                                     else 'migration_preview_failed', 409) from None
            with db.deserialize_snapshot(snapshot) as conn:
                counts = migration_mod.preview_counts(conn)
            pre_backup = self._publish_legacy_pre_backup(snapshot, records_before, kek)
            if pre_backup.get('status') != 'ok':
                raise OperationError('pre_backup_failed', 503, True)
            if len(self._migrations) >= MIGRATION_MAX_OPS:
                raise OperationError('maintenance_rate_limited', 503, True)
            op = migration_mod.MigrationOperation(
                snapshot=snapshot, digest=digest, kek=kek, dek=dek,
                old_token=old_token, records_before=records_before,
                counts=counts, pre_backup=pre_backup)
            key = secrets.token_urlsafe(16)
            self._migrations[key] = op
        return self._migration_view(key, op)

    def _publish_legacy_pre_backup(self, snapshot, records, kek):
        """schema1 前置保全：缺失库身份按契约临时生成 uuid4，不写回源库。"""
        try:
            salt = backup_module.snapshot_identity(snapshot)['salt']
            blob, header = backup_module.encrypt_package(
                snapshot, kek=kek, salt=salt,
                vault_id=str(uuid.uuid4()), restore_epoch=str(uuid.uuid4()),
                change_seq=0, db_schema_version=1, purpose='pre_migrate')
            self.backup_store().publish_verified(
                blob, header, kek=kek, expected_records=records,
                fault=self.backup_fault)
        except BackupError as exc:
            return {'status': 'failed', 'error_code': exc.code}
        except Exception:
            return {'status': 'failed', 'error_code': 'pre_backup_failed'}
        return {'status': 'ok', 'backup_id': header['backup_id'],
                'captured_at': header['captured_at'], 'db_schema_version': 1}

    def _migration_view(self, key, op):
        return {
            'operation_id': key,
            'confirmation_nonce': op.confirmation_nonce,
            'expires_in': max(0, int(op.expires_at - time.monotonic())),
            'source_format': 1,
            'counts': op.counts,
            'pre_backup': op.pre_backup,
            'active_vault_will_change': False,
            'warning': ('升级只作用于这份副本：不会与日常库合并、不会切换日常入口，'
                        '活动旧库不会被修改'),
        }

    def commit_migration(self, key, *, confirmation_nonce, confirm_upgrade=False,
                         fault=None):
        """屏障内单事务原位升级副本；提交后磁盘回读核验；再出后置 auto 包。"""
        from app import db
        fault = fault or (lambda node: None)
        op = self.get_migration(key)
        if op is None or op.status != 'prepared':
            raise OperationError('confirmation_stale', 409)
        if not hmac.compare_digest(op.confirmation_nonce, confirmation_nonce or ''):
            raise OperationError('invalid_confirmation', 401)
        if op.expires_at <= time.monotonic():
            self._migrations.pop(key, None)
            raise OperationError('confirmation_expired', 409)
        if confirm_upgrade is not True:
            raise OperationError('confirmation_required', 409)
        frozen = False
        snapshot_after = None
        try:
            with self.barrier(maintenance=True):
                # 提交前目标必须与 prepare 时逐字节一致
                try:
                    snapshot_before = db.snapshot_bytes(self.path)
                except Exception:
                    raise OperationError('migration_target_unavailable', 409) from None
                if hashlib.sha256(snapshot_before).hexdigest() != op.digest:
                    raise OperationError('migration_target_changed', 409)
                op.stage = 'confirmed'
                try:
                    with db.connection(self.path, readonly=False) as conn, \
                            db.transaction(conn):
                        migration_mod.upgrade_connection(
                            conn, op.kek, op.dek, op.old_token, fault=fault)
                        records = db.validate_records(conn, op.kek, op.dek)
                        if not migration_mod.business_records_match(
                                op.records_before, records):
                            raise OperationError('migration_mismatch', 500)
                    fault('migrate_after_commit')
                except OperationError:
                    raise
                except BackupError as exc:
                    raise OperationError(exc.code, 500) from None
                except Exception:
                    # 事务已整体回滚：副本保持格式1，可重新 prepare
                    raise OperationError('migration_failed', 500) from None
                op.stage = 'committed'
                # 提交后核验：从磁盘回读真实数据
                try:
                    snapshot_after = db.snapshot_bytes(self.path)
                    with db.deserialize_snapshot(snapshot_after) as conn:
                        disk_records = db.validate_records(conn, op.kek, op.dek)
                except Exception:
                    self._freeze_maintenance()
                    frozen = True
                    op.status = 'committed_data_invalid'
                    raise OperationError('committed_data_invalid', 500) from None
                if not migration_mod.business_records_match(
                        op.records_before, disk_records):
                    self._freeze_maintenance()
                    frozen = True
                    op.status = 'committed_data_invalid'
                    raise OperationError('committed_data_invalid', 500)
        except OperationError:
            if not frozen:
                # 提交前失败的确认不可重复使用；副本事务已回滚、保持格式1
                op.status = 'failed'
                op.stage = 'failed'
            raise
        finally:
            if frozen:
                self.maintenance = True  # 屏障退出后冻结继续生效（重启仍持续）
        # ---- 仅提交成功路径：后置自动备份；备份失败不冻结、可重试 ----
        op.status = 'committed'
        post_backup = self.backup_store().create(snapshot_after, kek=op.kek)
        op.post_backup = post_backup
        envelope = {'committed': True, 'source_format': 2,
                    'active_vault_changed': False, 'backup': post_backup}
        if post_backup.get('status') != 'ok':
            op.status = 'committed_backup_failed'
            return {**envelope, 'result': 'committed_backup_failed',
                    'retryable': True}
        op.stage = 'postverified'
        return {**envelope, 'result': 'committed', 'retryable': False}

    def retry_migration_backup(self, key):
        """只补后置备份：不重做迁移、不增序号；5 分钟操作期内有效。"""
        from app import db
        op = self.get_migration(key)
        if op is None or op.status != 'committed_backup_failed':
            raise OperationError('confirmation_stale', 409)
        probe = db.probe_format(self.path)
        if probe.state not in ('ready_locked', 'maintenance_failed'):
            raise OperationError('migration_retry_unavailable', 409)
        snapshot = db.snapshot_bytes(self.path)
        post_backup = self.backup_store().create(snapshot, kek=op.kek)
        op.post_backup = post_backup
        envelope = {'committed': True, 'source_format': 2,
                    'active_vault_changed': False, 'backup': post_backup}
        if post_backup.get('status') != 'ok':
            return {**envelope, 'result': 'committed_backup_failed', 'retryable': True}
        op.status = 'committed'
        op.stage = 'postverified'
        return {**envelope, 'result': 'committed', 'retryable': False}

    def rollback_prepare(self, kek, dek):
        """回退前只保全当前最新状态并核对；不执行覆盖、不用旧快照抹新数据。"""
        from app import db
        identity = self.current_identity()
        if identity is None:
            raise OperationError('vault_not_ready', 409)
        snapshot = db.snapshot_bytes(self.path)
        with db.deserialize_snapshot(snapshot) as conn:
            records = db.validate_records(conn, kek, dek)
        preserved = self.backup_store().create(
            snapshot, kek=kek, purpose='rollback_preserve', expected_records=records)
        if preserved.get('status') != 'ok':
            raise OperationError('rollback_preserve_failed', 503, True)
        return {
            'preserved': True,
            'purpose': 'rollback_preserve',
            'change_seq': identity['change_seq'],
            'backup': preserved,
            'active_vault_changed': False,
            'guidance': ('已先保全当前最新状态。回退不会用旧快照自动覆盖，'
                         '也不要把新版库交给旧版程序同时打开；正式回退需另行明确授权。'),
        }

    # ---------- 修改主密码（US3 T044/T045，FR-012～014） ----------

    def change_password(self, *, current_password, new_password, confirm_password):
        """协调改密全流程；任何前置校验失败都零写入，旧密码始终有效。

        次序（data-model 第 4 节）：类型闸门 → 验旧密码（401 优先）→
        新密码 6 位数字规则 → 两次一致 → 旧 KEK 前置保全（pre_migrate +
        password_change sidecar，失败 503 阻断）→ 单事务 KEK 重包换代 →
        磁盘回读核验 DEK 不变 → 新 KEK 后置 auto 包（失败不回滚）→ 自锁。
        """
        from app import db
        # 契约要求三个参数均为字符串；非字符串按规则违规拒绝，不放行任何写入
        if not all(isinstance(value, str) for value in
                   (current_password, new_password, confirm_password)):
            raise OperationError('password_rule_violated', 400)
        with self.barrier():
            # 1. 验旧密码：错误码优先级最高，失败不触碰任何写路径
            with db.connection(self.path, readonly=True) as conn:
                try:
                    old_kek, dek = db.credentials(conn, current_password)
                except ValueError:
                    raise OperationError('invalid_current_password', 401) from None
            # 2. 新密码规则：仅限 6 位数字，不引入其他强度规则
            if not PASSWORD_RULE.fullmatch(new_password):
                raise OperationError('password_rule_violated', 400)
            # 3. 两次输入一致；新旧相同允许成功，不额外禁止
            if new_password != confirm_password:
                raise OperationError('password_confirmation_mismatch', 400)
            # 4. 前置保全：旧 KEK 封装的 pre_migrate 包，是 SC-005 的旧密码恢复载体
            snapshot = db.snapshot_bytes(self.path)
            pre_backup = self.backup_store().create(
                snapshot, kek=old_kek, purpose='pre_migrate',
                trigger='password_change')
            if pre_backup.get('status') != 'ok':
                raise OperationError('pre_backup_failed', 503, True)
            # 5. 单事务重包：DEK/salt/KDF 不变，restore_epoch 换代、change_seq+1
            fault = self.password_change_fault  # 受控测试钩子；生产恒为 None
            with db.connection(self.path, readonly=False) as conn, \
                    db.transaction(conn):
                new_kek, new_seq = db.rewrap_master_password(
                    conn, new_password=new_password, dek=dek)
                if fault is not None:
                    fault('password_change_before_commit')
            # 6. 提交后磁盘回读：新密码可解，且解出的 DEK 与旧 DEK 逐字节相同
            with db.connection(self.path, readonly=True) as conn:
                _, verified_dek = db.credentials(conn, new_password)
            if verified_dek != dek:
                raise OperationError('committed_data_invalid', 500)
            if fault is not None:
                fault('password_change_after_commit')
            # 7. 后置 auto 备份（新 KEK 可解）；失败不回滚改密，沿用双结果语义
            post_backup = self.backup_store().create(
                db.snapshot_bytes(self.path), kek=new_kek)
            # 8. 成功即自锁：代次递增、全部内存会话清空，前端须以新密码重解
            self.lock_all()
            return {
                'changed': True,
                'persistence': {'saved': True, 'change_seq': new_seq},
                'backup': post_backup,
                'revoked_sessions': True,
                'requires_reunlock': True,
                'historical_backup_note': HISTORICAL_BACKUP_NOTE,
            }


_REGISTRY = {}
_REGISTRY_LOCK = threading.Lock()


def for_vault(path):
    key = str(Path(path).resolve()).casefold()
    with _REGISTRY_LOCK:
        if key not in _REGISTRY:
            _REGISTRY[key] = VaultOperations(path)
        return _REGISTRY[key]
