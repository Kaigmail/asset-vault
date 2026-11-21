"""单实例守护（T016）：进程锁 + 运行时发现文件 + 回环聚焦握手。

契约 contracts/desktop-runtime.md 条款 5（2026-11-08 修订版）：
- 复用 app.operations 的字节范围文件锁（T007 钉子已验证 frozen 形态有效），
  第二实例 claim 得 vault_in_use(423) 后不开窗、不抢锁，改走回环握手；
- 发现文件只放「端口 + 一次性聚焦口令」，不含通道凭证；聚焦口令仅能
  敲 POST /desktop/focus 一扇门，触不到任何 /api/* 业务接口；
- 发现文件落当前用户专属目录（默认 ACL 仅本人可读写），正常退出删除；
  进程异常死亡残留时，新实例抢锁成功即权威接管并无条件重写。
"""
from __future__ import annotations

import json
import os
import secrets
import time
from http.client import HTTPConnection
from pathlib import Path

from app import operations

DISCOVERY_FILE_NAME = "runtime-discovery.json"
# 运行态文件（非用户数据）：不进 data/、不进备份包，卸载语义独立
DEFAULT_DISCOVERY_DIR = Path(
    os.environ.get("LOCALAPPDATA", str(Path.home()))) / "AssetVault"


class AlreadyRunning(Exception):
    """第二实例信号：携带发现文件路径，供入口决定握手或提示后退出。"""

    def __init__(self, discovery_path: Path):
        self.discovery_path = Path(discovery_path)
        super().__init__("vault_already_running")


class SingleInstance:
    """一个桌面进程对应一个实例；管理器经 for_vault 与 Flask 工厂共享。"""

    def __init__(self, vault_path, *, discovery_dir=None):
        self._vault_path = Path(vault_path)
        self.discovery_dir = Path(
            discovery_dir) if discovery_dir else DEFAULT_DISCOVERY_DIR
        self.discovery_path = self.discovery_dir / DISCOVERY_FILE_NAME
        # 聚焦口令独立生成，与 runtime 的通道凭证不是同一张卡
        self.focus_secret = secrets.token_urlsafe(32)
        self._manager = None
        self._held = False

    @property
    def held(self) -> bool:
        return self._held

    def acquire(self) -> None:
        """抢进程锁；已有活实例时抛 AlreadyRunning，本进程不得继续开窗。"""
        # 与 create_app() 走同一个 for_vault 注册表，保证拿到的是同一个管理器
        manager = operations.for_vault(self._vault_path)
        try:
            manager.claim_process()
        except operations.OperationError as exc:
            if exc.code == "vault_in_use":
                raise AlreadyRunning(self.discovery_path) from None
            raise
        self._manager = manager
        self._held = True

    def publish(self, port: int) -> None:
        """服务起来后原子写入发现文件；抢锁成功方有资格写，旧残留被无条件覆盖。"""
        if not self._held:
            raise RuntimeError("single_instance_not_held")
        payload = {
            "pid": os.getpid(),
            "port": int(port),
            "focus_secret": self.focus_secret,
            "started_at": time.time(),
        }
        self.discovery_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self.discovery_path.with_name(DISCOVERY_FILE_NAME + ".tmp")
        tmp_path.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp_path, self.discovery_path)

    def verify_focus_secret(self, secret) -> bool:
        """供外层聚焦回调前复核；恒定时间比较，避免时序侧信道。"""
        return isinstance(secret, str) and \
            secrets.compare_digest(secret, self.focus_secret)

    def release(self) -> None:
        """关窗收尾最后一步：先删发现文件，再释放进程锁。"""
        try:
            if self.discovery_path.exists():
                self.discovery_path.unlink()
        finally:
            if self._manager is not None:
                self._manager.close()
                self._manager = None
                self._held = False

    @staticmethod
    def request_focus(discovery_dir=None, *, timeout: float = 5.0):
        """第二实例调用：读发现文件 → 带聚焦口令 POST 回环握手端点。

        返回 (是否成功, 原因码)；任何失败都不弹窗外动作，由入口统一提示。
        只连回环、不带通道凭证、不引入新 IPC 依赖。
        """
        base = Path(discovery_dir) if discovery_dir else DEFAULT_DISCOVERY_DIR
        path = base / DISCOVERY_FILE_NAME
        if not path.is_file():
            return False, "discovery_missing"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            port = int(payload["port"])
            secret = str(payload["focus_secret"])
        except (ValueError, KeyError, TypeError, OSError):
            return False, "discovery_invalid"
        if not (1 <= port <= 65535):
            return False, "discovery_invalid"
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=timeout)
            conn.request("POST", "/desktop/focus",
                         headers={"X-Focus-Secret": secret})
            response = conn.getresponse()
            body = response.read()
            conn.close()
        except OSError as exc:
            return False, type(exc).__name__
        ok = response.status == 200 and b"focused" in body
        return ok, f"http_{response.status}"
