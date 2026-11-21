"""桌面本地运行时（T015）：waitress 随机回环端口 + 外层通道闸门。

职责（契约 contracts/desktop-runtime.md 第 2/4/5 条）：
- 每次启动绑定 127.0.0.1:0 取随机端口，生成一次性通道凭证（仅存内存）；
- 在既有 Flask 工厂之外叠加一层外层闸门：Host 精确匹配、Origin 精确同源、
  /api/* 校验 X-Channel-Token；业务路由与既有同源/会话闸门一行不改；
- 附带单实例聚焦握手端点 POST /desktop/focus（独立聚焦口令，非通道凭证）；
- stop() 幂等，关停后端口须可立即重新绑定（T004 钉子已验证）。

本模块只依赖 Flask/waitress 标准组合，不 import pywebview，可在无窗口
环境下经短时子进程或进程内测试直接驱动。
"""
from __future__ import annotations

import secrets
import threading

from flask import jsonify, request

# 注：浏览器开发入口的保留端口不在此写字面量——桌面运行时只绑 :0 随机端口，
# 「永不占用保留端口」由审计层 socket 拦截、子进程白名单与 T012 端口矩阵三层守卫。
FOCUS_PATH = "/desktop/focus"
CHANNEL_HEADER = "X-Channel-Token"
FOCUS_HEADER = "X-Focus-Secret"


class DesktopRuntime:
    """一次桌面启动对应一个实例；随关窗收尾丢弃，不跨进程复用。"""

    def __init__(self, app, *, on_focus=None):
        self._app = app
        self._on_focus = on_focus
        self._server = None
        self._thread = None
        self._gate_installed = False
        self.token = None        # 通道凭证：只活在本实例内存
        self.port = None
        self.focus_secret = None  # 聚焦口令：仅能敲 /desktop/focus 一扇门
        self.allowed_origins = ()

    # ---------- 生命周期 ----------

    def configure_focus(self, focus_secret, on_focus):
        """登记单实例聚焦口令与聚焦回调（由 single_instance 在 start 前注入）。"""
        self.focus_secret = focus_secret
        self._on_focus = on_focus

    def start(self) -> int:
        from waitress import create_server

        self.token = secrets.token_urlsafe(32)
        self._install_gate()
        # 只绑 IPv4 回环：不绑 0.0.0.0/::，外部机器不可达
        server = create_server(self._app, host="127.0.0.1", port=0)
        port = int(server.effective_port)  # Windows 上可能返回字符串，统一转 int
        if port == 0:  # 未分配端口；保留端口的拒绝由审计层与测试矩阵负责
            server.close()
            raise RuntimeError("desktop_runtime_unexpected_port")
        self.port = port
        self.allowed_origins = (f"http://127.0.0.1:{port}", f"http://localhost:{port}")
        self._server = server
        self._thread = threading.Thread(
            target=server.run, name="desktop-waitress", daemon=True)
        self._thread.start()
        return port

    def stop(self):
        """停止接受新连接并释放端口；重复调用安全。"""
        server = self._server
        self._server = None
        if server is not None:
            server.close()

    # ---------- 外层闸门 ----------

    def _install_gate(self):
        if self._gate_installed:
            return
        self._gate_installed = True
        runtime = self

        @self._app.before_request
        def _desktop_channel_gate():
            # 1) Host 必须精确等于本次随机端口的两个回环名之一；
            #    不信任 X-Forwarded-*，不允许任意子域。
            if request.host not in (f"127.0.0.1:{runtime.port}",
                                    f"localhost:{runtime.port}"):
                return jsonify(error="非法的主机来源", code="bad_host",
                               retryable=False), 403

            # 2) 聚焦握手端点：本地进程发起、无浏览器 Origin，独立口令校验，
            #    不走通道凭证与同源 Origin 规则。
            if request.path == FOCUS_PATH:
                if request.method != "POST":
                    return jsonify(error="方法不支持", code="method_not_allowed",
                                   retryable=False), 405
                if runtime.focus_secret is None or \
                        request.headers.get(FOCUS_HEADER) != runtime.focus_secret:
                    return jsonify(error="聚焦凭证缺失或错误", code="focus_required",
                                   retryable=False), 401
                if callable(runtime._on_focus):
                    runtime._on_focus()
                return jsonify(focused=True), 200

            # 3) Origin：存在即须精确同源（null/外域一律 403）；
            #    桌面窗口的写入/解锁/维护请求必须带同源 Origin。
            origin = request.headers.get("Origin")
            if origin is not None and origin not in runtime.allowed_origins:
                return jsonify(error="非法的来源", code="bad_origin",
                               retryable=False), 403
            write = request.method not in ("GET", "HEAD", "OPTIONS")
            if write and origin is None:
                return jsonify(error="缺少同源来源", code="origin_required",
                               retryable=False), 403

            # 4) 通道凭证只管 /api/*：页面与静态资源不要求该头
            #    （首页本身是凭证注入载体）。
            if request.path.startswith("/api/") and \
                    request.headers.get(CHANNEL_HEADER) != runtime.token:
                return jsonify(error="桌面通道凭证缺失或错误",
                               code="channel_required", retryable=False), 401
            return None  # 放行，进入既有蓝图闸门与业务路由
