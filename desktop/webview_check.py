"""WebView2 运行环境启动期检测与补齐引导（T019，FR-003 启动段）。

固定 EdgeChromium 引擎、无引擎回退：运行时缺失时不得静默失败，必须给出
可执行的补齐指引。安装期检测在 Phase 2 安装器脚本内同构实现；本模块负责
启动期，注册表三视图与 T006 钉子的检测写法保持一致。

注册表读取与弹窗/打开动作全部可注入，单测无需触碰真实注册表与 UI。
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

WEBVIEW2_CLIENT_KEY = (
    r"SOFTWARE\Microsoft\EdgeUpdate\Clients"
    r"\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}")
# winreg 常量字面量（避免在模块顶层 import winreg，保持非 Windows 环境可导入）
_HKLM = -2147483646
_HKCU = -2147483647

GUIDE_TEXT = (
    "本程序需要 Microsoft Edge WebView2 运行时才能启动，当前电脑未检测到该环境。\n\n"
    "请安装 WebView2 Evergreen Runtime 后重新启动本程序；"
    "若安装包已附带运行时安装程序，将自动为你打开。")


@dataclass(frozen=True)
class WebView2Status:
    available: bool
    version: str | None
    location: str | None  # HKLM64 / HKLM32 / HKCU / None


def _default_reader(root: int, subkey: str, value: str) -> str:
    import winreg  # 仅 Windows 产品路径导入

    with winreg.OpenKey(root, subkey) as handle:
        return winreg.QueryValueEx(handle, value)[0]


def _candidate_views():
    return (
        ("HKLM64", _HKLM, WEBVIEW2_CLIENT_KEY),
        ("HKLM32", _HKLM,
         WEBVIEW2_CLIENT_KEY.replace(r"SOFTWARE\Microsoft",
                                     r"SOFTWARE\WOW6432Node\Microsoft")),
        ("HKCU", _HKCU, WEBVIEW2_CLIENT_KEY),
    )


def detect_webview2(reader=None) -> WebView2Status:
    """三视图依次探测 pv 版本值；任一命中即视为可用，全部缺失才判定缺失。"""
    read = reader or _default_reader
    for location, root, subkey in _candidate_views():
        try:
            pv = read(root, subkey, "pv")
        except OSError:
            continue
        if isinstance(pv, str) and pv.strip():
            return WebView2Status(True, pv.strip(), location)
    return WebView2Status(False, None, None)


def ensure_or_guide(*, reader=None, message_box=None, opener=None,
                    bootstrapper=None) -> WebView2Status:
    """可用即放行；缺失则弹可执行指引，并在有内嵌 Bootstrapper 时打开它。

    message_box/opener 由入口注入真实实现（ctypes MessageBoxW / os.startfile
    的受控封装）；缺失引导永不尝试回退旧引擎。
    """
    status = detect_webview2(reader)
    if status.available:
        return status
    if callable(message_box):
        message_box(GUIDE_TEXT)
    if bootstrapper is not None and opener is not None:
        bootstrapper_path = Path(bootstrapper)
        if bootstrapper_path.is_file():
            opener(str(bootstrapper_path))
    return status
