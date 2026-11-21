"""桌面应用入口编排（T017，FR-001/005/006/007）。

启动顺序：WebView2 检测 → 单实例判定 → 起随机端口本地服务 → 发布发现文件
→ pywebview 固定 EdgeChromium 开窗并注入通道凭证 → 关窗四步收尾。

main() 另承担维护参数分派：`--pre-upgrade-backup`/`--wipe-data` 命中时直接
转交 desktop.maintenance，不开窗、不加载 pywebview 栈，以退出码回答安装器。

产品 main() 不带任何测试参数；测试经 run() 的关键字参数注入沙盒路径、
替身 opener/message_box 与自动关窗计时。pywebview/pythonnet 延迟到开窗
分支才导入：第二实例与环境缺失分支不加载窗口栈，保证「第二实例开窗数为零」。
"""
from __future__ import annotations

import ctypes
import json
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

from app import db
from app.main import create_app
from desktop import webview_check
from desktop.navigation import ExternalLinkApi, install_navigation_guard
from desktop.runtime import DesktopRuntime
from desktop.single_instance import AlreadyRunning, SingleInstance

WINDOW_TITLE = "Asset Vault"
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 860
PORT_WAIT_TIMEOUT = 5.0


def _message_box(text: str) -> None:
    """原生提示框（无窗口栈依赖）：MB_OK | MB_ICONWARNING。"""
    user32 = ctypes.windll.user32
    user32.MessageBoxW(0, text, WINDOW_TITLE, 0x00000030)


def _bring_window_to_front(window) -> None:
    """聚焦握手回调：恢复最小化并置顶前台（Win32，无新依赖）。"""
    native = getattr(window, "native", None)
    if native is None:
        return
    hwnd = native.Handle.ToInt64()
    user32 = ctypes.windll.user32
    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    user32.SetForegroundWindow(hwnd)


def _wait_port_released(port: int, timeout: float = PORT_WAIT_TIMEOUT) -> bool:
    """关窗收尾第三步：轮询确认回环端口已无监听。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            state = sock.connect_ex(("127.0.0.1", port))
        finally:
            sock.close()
        if state != 0:
            return True
        time.sleep(0.05)
    return False


def _shutdown(manager, runtime, instance, port: int) -> list[str]:
    """关窗四步，顺序不可颠倒（契约「窗口生命周期」节）。"""
    order = []
    manager.lock_all()                 # ① 换代、清空全部内存会话与密钥引用
    order.append("lock_all")
    runtime.stop()                     # ② 停止 waitress
    order.append("stop_runtime")
    if _wait_port_released(port):      # ③ 确认端口释放
        order.append("port_released")
    else:
        order.append("port_release_timeout")
    instance.release()                 # ④ 删发现文件、释放进程锁
    order.append("release_instance")
    return order


def run(*, vault_path=None, discovery_dir=None, auto_close_after=None,
        message_box=None, opener=None, bootstrapper=None, on_ready=None,
        focus_flag_path=None) -> dict:
    """编排一次桌面启动；返回结果字典供入口与测试共同消费。"""
    message_box = message_box or _message_box
    opener = opener or webbrowser.open
    result = {"outcome": None, "windows_created": 0, "shutdown_order": []}

    # 1) WebView2 可用性检测：缺失即引导，不静默失败、不回退旧引擎
    status = webview_check.ensure_or_guide(
        message_box=message_box, opener=opener, bootstrapper=bootstrapper)
    if not status.available:
        result.update(outcome="webview2_missing")
        return result
    result["webview2"] = {"version": status.version, "location": status.location}

    # 2) 单实例判定：抢锁失败即握手聚焦后退出，本进程不开窗
    target_vault = Path(vault_path) if vault_path else db.DB_PATH
    instance = SingleInstance(target_vault, discovery_dir=discovery_dir)
    try:
        instance.acquire()
    except AlreadyRunning:
        ok, reason = SingleInstance.request_focus(discovery_dir)
        if not ok:
            # 契约条款 5：握手无法完成（发现文件缺失/损坏/连接失败/401）时
            # 明确提示后退出；内部原因码只进结果字典，不弹给用户
            message_box("程序已在运行。如未看到程序窗口，请关闭已有实例后再试。")
        result.update(outcome="already_running", focused=ok,
                      reason=reason, windows_created=0)
        return result

    # 3) 既有 Flask 工厂（不重复抢锁），通道差异在运行时装配层
    app = create_app(claim_process=False)
    manager = app.extensions["vault_operations"]

    focus_holder = {"window": None}

    def _on_focus():
        if focus_flag_path is not None:
            Path(focus_flag_path).write_text("focused", encoding="utf-8")
        _bring_window_to_front(focus_holder["window"])

    runtime = DesktopRuntime(app, on_focus=_on_focus)
    runtime.configure_focus(instance.focus_secret, _on_focus)
    port = runtime.start()
    # 随机端口确定后再回填蓝图同源闸门的允许 Origin
    app.config["VAULT_ALLOWED_ORIGINS"] = runtime.allowed_origins
    instance.publish(port)
    result.update(port=port)

    # 4) pywebview 固定 EdgeChromium 开窗（延迟导入：前述分支不加载窗口栈）
    import webview

    external_api = ExternalLinkApi(opener=opener)
    window = webview.create_window(
        WINDOW_TITLE, f"http://127.0.0.1:{port}/",
        js_api=external_api, width=WINDOW_WIDTH, height=WINDOW_HEIGHT)
    focus_holder["window"] = window
    result["windows_created"] = 1
    guard_installed = {"done": False}

    def _on_loaded():
        # 凭证只注入页面 JS 内存；刷新触发本事件时重新注入，绝不写 localStorage
        window.evaluate_js(
            "window.__AV_DESKTOP__="
            + json.dumps({"token": runtime.token}) + ";")
        if not guard_installed["done"]:
            install_navigation_guard(window, opener=opener)
            guard_installed["done"] = True

    window.events.loaded += _on_loaded

    if auto_close_after is not None:
        # 测试专用：定时模拟用户关窗，产品入口永不传此参数
        def _auto_close():
            time.sleep(float(auto_close_after))
            window.destroy()
        threading.Thread(target=_auto_close, name="auto-close",
                         daemon=True).start()

    if callable(on_ready):
        on_ready(port, runtime.token, instance, window)

    # 5) 阻塞至关窗；固定引擎，无回退
    webview.start(gui="edgechromium")

    # 6) 关窗四步收尾（主线程执行，顺序可断言）
    result["shutdown_order"] = _shutdown(manager, runtime, instance, port)
    result["outcome"] = "closed"
    return result


# 维护模式参数：命中即走无窗口 CLI 分派（安装器契约，见
# contracts/desktop-runtime.md「维护命令」节）。frozen 只有一个 exe，
# 安装器以 AssetVault.exe --pre-upgrade-backup 形式调用，退出码即契约。
MAINTENANCE_FLAGS = ("--pre-upgrade-backup", "--wipe-data")


def main(argv=None) -> int:
    """PyInstaller 入口薄壳：维护参数无窗口分派，其余走完整桌面外壳。"""
    arguments = sys.argv[1:] if argv is None else list(argv)
    if any(flag in arguments for flag in MAINTENANCE_FLAGS):
        # 延迟导入：维护路径不加载 maintenance 之外的任何窗口相关依赖
        from desktop.maintenance import main as maintenance_main
        return maintenance_main(arguments)
    # 产品外壳：真实路径、真实 UI，无测试参数
    result = run()
    return 0 if result["outcome"] in ("closed",) else 2


if __name__ == "__main__":
    raise SystemExit(main())
