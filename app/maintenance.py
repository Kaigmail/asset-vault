# -*- coding: utf-8 -*-
"""数据目录维护核心（app 层，FR-004/FR-009）：升级前置保全与删除全部数据。

分层纪律：本模块是维护操作的唯一核心实现，app/ 不反向依赖 desktop/——
桌面 CLI（desktop/maintenance.py）与 Flask 维护端点（app/api.py）都是薄入口，
共同复用这里的 core 函数。core 不依赖任何测试设施/窗口栈/socket，路径全部
显式传参，frozen 形态可直接调用。

两条调用路径的锁分工：
- CLI/安装器路径（wipe_data/pre_upgrade_backup）：自行 claim_process 抢字节锁，
  已有实例运行时以 vault_in_use 语义失败，不与运行中的程序争用数据目录；
- 进程内 HTTP 路径（wipe_data_contents）：桌面运行时已由共享 manager 持有
  进程字节锁，本函数不抢锁、不删锁文件，确认校验由请求边界完成。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.operations import OperationError, VaultOperations

# 退出码是安装器契约的一部分，固定不复用 0/1/2 之外的常规语义冲突；
# HTTP 路径不直接使用退出码，而由 api 层把稳定机器码翻译为 HTTP 状态
EXIT_OK = 0
EXIT_BAD_USAGE = 2
EXIT_CONFIRMATION_REQUIRED = 3
EXIT_VAULT_IN_USE = 4
EXIT_NO_VAULT = 5
EXIT_MAINTENANCE_FAILED = 6

SNAPSHOTS_DIRNAME = "rollback-snapshots"
LOCK_SUFFIX = ".lck"


class MaintenanceError(RuntimeError):
    """维护操作失败；code 是稳定机器码，exit_code 是安装器可见的进程退出码。"""

    def __init__(self, code: str, exit_code: int, message: str = ""):
        super().__init__(message or code)
        self.code = code
        self.exit_code = exit_code


def sha256_file(path: Path) -> str:
    """分块 sha256，避免大库一次性读入内存。"""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_file(src: Path, dst: Path) -> None:
    """模块级复制函数：受控测试可替换以注入 ENOSPC/短写类故障。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _claim_lock(db_path: Path) -> VaultOperations:
    """抢进程字节锁；已有实例运行时翻译为维护语义错误。"""
    manager = VaultOperations(db_path)
    try:
        manager.claim_process()
    except OperationError as exc:
        if exc.code == "vault_in_use":
            raise MaintenanceError("vault_in_use", EXIT_VAULT_IN_USE) from exc
        raise MaintenanceError("maintenance_failed", EXIT_MAINTENANCE_FAILED) from exc
    return manager


def _read_identity(db_path: Path) -> dict:
    """只读 meta 身份：只取结构标识，绝不读取资产字段内容（宪法原则 IV）。"""
    identity = {"vault_id": None, "change_seq": None}
    # 注意：sqlite 连接的 with 只管事务不管关闭，必须显式 close，
    # 否则 Windows 上残留句柄会锁住 staging 目录，导致后续 os.replace 拒绝访问
    conn = None
    try:
        uri = db_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        rows = dict(conn.execute(
            "SELECT key, value FROM meta "
            "WHERE key IN ('vault_id', 'change_seq')").fetchall())
        identity["vault_id"] = rows.get("vault_id")
        seq = rows.get("change_seq")
        identity["change_seq"] = int(seq) if seq is not None and seq.isdigit() else None
    except (sqlite3.Error, OSError, ValueError):
        # 身份读不到不否决字节级保全；manifest 如实记录 None
        pass
    finally:
        if conn is not None:
            conn.close()
    return identity


def _integrity_check(db_path: Path) -> str:
    uri = db_path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        return conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        # 同上：显式释放文件句柄，避免锁住待改名的 staging 目录
        conn.close()


def pre_upgrade_backup(data_dir: str | Path) -> dict:
    """对 data/ 做文件级保全副本并回读验证（方案 A，无需主密码）。

    布局：data/rollback-snapshots/snapshot-<UTC>/，先写 .staging-* 临时目录，
    全部复制与校验通过后整体改名发布；任一步失败清理 staging、源目录只读。
    """
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        raise MaintenanceError("data_dir_missing", EXIT_NO_VAULT)
    db_path = data_dir / "vault.db"
    if not db_path.is_file():
        raise MaintenanceError("vault_not_found", EXIT_NO_VAULT)

    manager = _claim_lock(db_path)
    snapshots_dir = data_dir / SNAPSHOTS_DIRNAME
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    # 上次运行若被 TerminateProcess/断电中断，其 .staging-* 没机会走异常清理；
    # 发布物永远是 snapshot-* 前缀，点前缀临时目录可在新一次保全开始时安全清扫
    for stale in snapshots_dir.glob(".staging-*"):
        if stale.is_dir() and not stale.is_symlink():
            shutil.rmtree(stale, ignore_errors=True)
    stamp = _utc_stamp()
    staging = snapshots_dir / f".staging-{stamp}-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        # 1) 字节复制：跳过快照目录自身（防自引用滚雪球）与运行态锁文件
        files: list[dict] = []
        for item in sorted(data_dir.rglob("*")):
            if item == snapshots_dir or snapshots_dir in item.parents:
                continue
            if item.is_dir() or item.suffix == LOCK_SUFFIX:
                continue
            rel = item.relative_to(data_dir)
            _copy_file(item, staging / rel)
            files.append({
                "relative": rel.as_posix(),
                "size": item.stat().st_size,
                "sha256": sha256_file(item),
            })

        # 2) 回读验证：副本逐文件 sha256/大小与源一致
        for entry in files:
            copied = staging / entry["relative"]
            if not copied.is_file() \
                    or copied.stat().st_size != entry["size"] \
                    or sha256_file(copied) != entry["sha256"]:
                raise MaintenanceError("backup_verification_failed",
                                       EXIT_MAINTENANCE_FAILED, entry["relative"])

        # 3) 副本库完整性 + 只读身份
        copied_db = staging / "vault.db"
        integrity = _integrity_check(copied_db)
        if integrity != "ok":
            raise MaintenanceError("integrity_check_failed",
                                   EXIT_MAINTENANCE_FAILED, integrity)
        identity = _read_identity(copied_db)

        manifest = {
            "trigger": "pre_upgrade",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "db_integrity": integrity,
            "vault_id": identity["vault_id"],
            "change_seq": identity["change_seq"],
            "files": files,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8")

        # 4) 同秒连发时让出不冲突的发布名，再整体原子改名
        target = snapshots_dir / f"snapshot-{stamp}"
        suffix = 2
        while target.exists():
            target = snapshots_dir / f"snapshot-{stamp}-{suffix}"
            suffix += 1
        os.replace(staging, target)
        return {"status": "ok", "trigger": "pre_upgrade",
                "snapshot_dir": str(target), "file_count": len(files)}
    except MaintenanceError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise MaintenanceError("backup_failed", EXIT_MAINTENANCE_FAILED,
                               type(exc).__name__) from exc
    except Exception as exc:  # 兜底：任何意外都不得留下半成品快照
        shutil.rmtree(staging, ignore_errors=True)
        raise MaintenanceError("backup_failed", EXIT_MAINTENANCE_FAILED,
                               type(exc).__name__) from exc
    finally:
        manager.close()


def wipe_data_contents(data_dir: str | Path) -> dict:
    """删除数据目录全部内容、保留空目录本身与运行态锁文件（进程内路径核心）。

    与 CLI 路径 wipe_data 的分工：本函数不抢字节锁、不做确认校验——调用方
    必须已持有进程锁（桌面运行时的共享 manager），并在请求边界完成双确认。
    vault.db.lck 归持锁 manager 的生命周期管理，此处跳过，绝不删自己的租约；
    占用/权限受限如实抛错，不报假成功（FR-004）。
    """
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        raise MaintenanceError("data_dir_missing", EXIT_NO_VAULT)
    try:
        for child in sorted(data_dir.iterdir()):
            # 运行态锁文件（文件名随库名，统一按 .lck 后缀识别）归持锁
            # manager 的生命周期管理，此处跳过，绝不删自己的租约；其余全清
            if child.suffix == LOCK_SUFFIX:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    except OSError as exc:
        raise MaintenanceError("wipe_failed", EXIT_MAINTENANCE_FAILED,
                               type(exc).__name__) from exc
    return {"status": "wiped", "data_dir": str(data_dir)}


def wipe_data(data_dir: str | Path, *, confirm: bool = False) -> dict:
    """CLI/安装器路径：缺省拒绝，必须显式 confirm=True（契约 409 语义）。

    自行抢进程字节锁后复用 wipe_data_contents，收尾释放锁并删除锁文件；
    已有实例运行时以 vault_in_use 语义失败，不争用数据目录。
    """
    if confirm is not True:
        raise MaintenanceError("wipe_confirmation_required",
                               EXIT_CONFIRMATION_REQUIRED)
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        raise MaintenanceError("data_dir_missing", EXIT_NO_VAULT)

    db_path = data_dir / "vault.db"
    manager = _claim_lock(db_path)
    try:
        result = wipe_data_contents(data_dir)
    finally:
        manager.close()
        lock_file = data_dir / (db_path.name + LOCK_SUFFIX)
        if lock_file.is_file():
            lock_file.unlink()
    return result
