"""本机非敏感设置存储（Spec-002 US4；data-model.md 第 3 节）。

职责与边界：
- 设置落 ``data/settings.json``，与加密库分离：不进加密库、不进 avbak 备份包、
  不联网、不上报；丢失或损坏只意味着回到「AI 默认关闭」的安全态；
- 读取宽容、写入严格：文件缺失/损坏/异型一律回安全默认（两个布尔皆 false），
  绝不抛错阻断程序启动；写入只接受白名单键的布尔值；
- 原子写（``.writing`` 临时文件 → fsync → 磁盘回读 → ``os.replace``），文件套用
  备份模块同款受限 ACL（仅当前用户/SYSTEM/Administrators）；
- 本模块位于 app 层，**不得反向依赖 desktop/**，Spec-001 测试环境不引入 pywebview；
- 路径在每次调用时从 ``db.DATA_DIR`` 动态解析——测试靠 monkeypatch 把数据目录
  重定向到沙盒，import 期固化路径会使沙盒断言整体失效。
"""
import json
import os
from pathlib import Path

from app.backup import (
    TEMP_SUFFIX,
    BackupError,
    canonical_bytes,
    check_permissions,
    protect,
)

SETTINGS_FILENAME = "settings.json"
SETTINGS_VERSION = 1

# 安全默认：全新安装、升级后无设置文件、文件损坏三种场景统一回到此状态（FR-015）
DEFAULT_SETTINGS = {
    "version": SETTINGS_VERSION,
    "ai_enabled": False,
    "ai_risk_prompt_suppressed": False,
}
_BOOL_KEYS = ("ai_enabled", "ai_risk_prompt_suppressed")


class SettingsError(RuntimeError):
    """只含稳定错误码，不含路径、字段值或底层系统消息。"""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def settings_path() -> Path:
    """设置文件路径；调用时动态解析，确保跟随测试沙盒对 db.DATA_DIR 的重定向。"""
    from app import db
    return db.DATA_DIR / SETTINGS_FILENAME


def _coerce(raw) -> dict:
    """白名单提取：仅采纳布尔值，非布尔/异型回 false，未知键丢弃，version 规范化。"""
    settings = dict(DEFAULT_SETTINGS)
    if isinstance(raw, dict):
        for key in _BOOL_KEYS:
            value = raw.get(key)
            if isinstance(value, bool):
                settings[key] = value
    return settings


def load_settings() -> dict:
    """读取设置；任何缺失、损坏或读取异常都回安全默认，绝不抛出。"""
    try:
        raw = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_SETTINGS)
    return _coerce(raw)


def is_ai_enabled() -> bool:
    """AI 总开关当前状态；默认关闭，任何不确定状态都按关闭处理。"""
    return bool(load_settings()["ai_enabled"])


def save_settings(*, ai_enabled: bool, ai_risk_prompt_suppressed: bool) -> dict:
    """严格写入并返回落盘后的规范化设置；失败抛 SettingsError，不留半成品。

    参数校验先于任何磁盘 IO；临时文件与正式文件均核验受限 DACL，发布后再回读一道。
    """
    if not isinstance(ai_enabled, bool) \
            or not isinstance(ai_risk_prompt_suppressed, bool):
        raise ValueError("settings_fields_must_be_boolean")
    path = settings_path()
    payload = canonical_bytes({
        "version": SETTINGS_VERSION,
        "ai_enabled": ai_enabled,
        "ai_risk_prompt_suppressed": ai_risk_prompt_suppressed,
    })
    temp = path.with_name(path.name + TEMP_SUFFIX)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temp.open("xb") as stream:
            protect(temp)
            check_permissions(temp)
            if stream.write(payload) != len(payload):
                raise SettingsError("settings_persistence_failed")
            stream.flush()
            os.fsync(stream.fileno())
        check_permissions(temp)
        if temp.read_bytes() != payload:  # 磁盘回读门：短写/篡改一律拒发
            raise SettingsError("settings_persistence_failed")
        os.replace(temp, path)            # 同目录原子改名，允许覆盖既有设置
        check_permissions(path)
    except SettingsError:
        raise
    except (BackupError, OSError) as exc:
        # ACL 失败与 IO 失败统一稳定机器码，前端按 503 可重试呈现
        raise SettingsError("settings_persistence_failed") from exc
    finally:
        if temp.exists():
            try:
                temp.unlink()
            except OSError:
                pass
    return load_settings()


def set_ai_enabled(enabled: bool) -> dict:
    """只改总开关，提示偏好保持原值（两个设置独立存储、互不派生）。"""
    current = load_settings()
    return save_settings(
        ai_enabled=enabled,
        ai_risk_prompt_suppressed=current["ai_risk_prompt_suppressed"],
    )


def set_risk_prompt_suppressed(suppress: bool) -> dict:
    """只改「不再提示」偏好，总开关保持原值。"""
    current = load_settings()
    return save_settings(
        ai_enabled=current["ai_enabled"],
        ai_risk_prompt_suppressed=suppress,
    )
