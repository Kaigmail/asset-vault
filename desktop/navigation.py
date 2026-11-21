"""窗口导航拦截（T018，FR-007）。

窗口只加载本机可信界面，三层防线：
1. CoreWebView2.NavigationStarting：同窗口外域/非 http(s) 导航一律 Cancel，
   改交系统默认浏览器；
2. pywebview js_api（ExternalLinkApi）：页面外链点击显式请求系统浏览器打开；
3. pywebview 内置 NewWindowRequested 已默认把 target=_blank 交系统浏览器
   （OPEN_EXTERNAL_LINKS_IN_BROWSER 默认 True），本模块不改其行为。

所有判定与动作可注入、可无窗口单测；真实控件订阅在 install_navigation_guard。
"""
from __future__ import annotations

import time
import urllib.parse
import webbrowser

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})


def is_external_navigation(uri, allowed_hosts=LOOPBACK_HOSTS) -> bool:
    """判定 URI 是否为窗口外导航。

    http(s) 且主机名在回环白名单内 → 本机可信；其余 http(s) 主机、
    file/data/about 等非 http(s) 协议 → 外部。相对 URL（无 scheme）不算外链。
    """
    if not isinstance(uri, str) or not uri:
        return False
    try:
        parsed = urllib.parse.urlsplit(uri)
    except ValueError:
        return True
    if not parsed.scheme:
        return False  # 相对路径：窗口内正常路由
    if parsed.scheme not in ("http", "https"):
        return True
    host = (parsed.hostname or "").lower()
    return host not in frozenset(allowed_hosts)


class ExternalLinkApi:
    """暴露给页面 JS 的唯一桥对象（window.pywebview.api.open_external）。

    不暴露任何其他 Python 调用面；只负责把确认过的外链交系统浏览器。
    """

    def __init__(self, *, opener=None, allowed_hosts=LOOPBACK_HOSTS):
        self._opener = opener or webbrowser.open
        self._allowed = frozenset(allowed_hosts)
        self.opened = []  # 测试与验收入口的观察点，产品路径无副作用

    def open_external(self, url):
        if not isinstance(url, str) or \
                not is_external_navigation(url, self._allowed):
            return {"opened": False, "reason": "not_external"}
        self.opened.append(url)
        self._opener(url)
        return {"opened": True, "url": url}


def attach_navigation_guard(core_webview, allowed_hosts, opener):
    """在 CoreWebView2 实例上订阅 NavigationStarting，返回挂载的 handler。"""

    def on_navigation_starting(sender, args):
        uri = str(args.get_Uri())
        if is_external_navigation(uri, allowed_hosts):
            args.set_Cancel(True)
            opener(uri)

    core_webview.NavigationStarting += on_navigation_starting
    return [on_navigation_starting]


def _ui_invoke(native, fn):
    """WinForms UI 线程同步调度：本模块唯一的 pythonnet 依赖点（测试可替换）。"""
    from System import Action

    box = {}
    native.Invoke(Action(lambda: box.__setitem__("value", fn())))
    return box.get("value")


def _on_ui_thread(native, fn):
    """把 WinForms 控件访问 marshal 到 UI 线程。

    CoreWebView2 是 COM 对象，只允许在创建它的 UI 线程访问（跨线程抛
    InvalidOperationException）；pywebview 的 loaded 事件却在事件分发线程
    执行。无 Invoke 能力的合成对象（单元测试替身）直接同步执行。
    """
    if not getattr(native, "InvokeRequired", False):
        return fn()
    return _ui_invoke(native, fn)


def _read_core(control):
    """UI 线程内读取 CoreWebView2；初始化未完成/失败时返回 None 而不抛。"""
    try:
        return control.CoreWebView2
    except Exception:  # .NET InvalidOperationException 等：视为尚未就绪
        return None


def install_navigation_guard(window, *, opener=None, allowed_hosts=LOOPBACK_HOSTS,
                             timeout: float = 15.0):
    """从 pywebview 窗口解析 CoreWebView2 并挂拦截；控件未就绪时短时轮询。

    控件对象链（pywebview 6.2.1 winforms/edgechromium）：
    window.native(BrowserForm).browser(EdgeChrome).webview(WebView2).CoreWebView2
    所有真实控件访问都经 _on_ui_thread 回到 WinForms UI 线程。
    """
    opener = opener or webbrowser.open
    deadline = time.monotonic() + timeout
    native = core = None
    while time.monotonic() < deadline:
        native = getattr(window, "native", None)
        browser = getattr(native, "browser", None)
        control = getattr(browser, "webview", None)
        if native is not None and control is not None:
            core = _on_ui_thread(native, lambda: _read_core(control))
        if core is not None:
            break
        time.sleep(0.1)
    if core is None:
        raise RuntimeError("webview2_core_not_ready")
    return _on_ui_thread(
        native, lambda: attach_navigation_guard(core, allowed_hosts, opener))
