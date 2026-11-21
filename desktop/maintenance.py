# -*- coding: utf-8 -*-
"""T030/T031 维护模式 CLI 薄包装：升级前置保全与删除全部数据（FR-004/FR-009）。

核心实现已下沉到 app/maintenance.py（app 层，HTTP 维护端点与本 CLI 共用）；
本模块只保留安装器可见的命令行形态：argparse 参数解析、frozen 数据目录推断、
JSON 输出与退出码翻译。两条子命令均不开窗、不导入 webview 栈、不监听任何端口，
以退出码表达成败，安装器只认退出码（契约见
specs/002-desktop-app/contracts/desktop-runtime.md「维护命令」节）。

开发态守卫禁止开发根存在 data/，故开发/测试必须显式传 --data-dir。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 核心统一从 app 层复用；显式再导出保持既有调用方/测试的导入路径稳定
from app.maintenance import (  # noqa: F401
    EXIT_BAD_USAGE,
    EXIT_CONFIRMATION_REQUIRED,
    EXIT_MAINTENANCE_FAILED,
    EXIT_NO_VAULT,
    EXIT_OK,
    EXIT_VAULT_IN_USE,
    LOCK_SUFFIX,
    SNAPSHOTS_DIRNAME,
    MaintenanceError,
    pre_upgrade_backup,
    sha256_file,
    wipe_data,
    wipe_data_contents,
)


def default_data_dir() -> Path:
    """frozen 形态取 exe 旁 data/；源码形态取项目根 data/（开发态被守卫禁建）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data"
    return Path(__file__).resolve().parents[1] / "data"


def _emit(payload: dict, *, error: bool = False) -> None:
    """windowed 形态下 stdout/stderr 可能为 None，静默跳过而非崩溃。"""
    stream = sys.stderr if error else sys.stdout
    if stream is not None:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="desktop.maintenance",
        description="Asset Vault 维护模式（不开窗、不监听端口）")
    parser.add_argument("--pre-upgrade-backup", action="store_true",
                        help="覆盖安装前文件级保全并回读验证")
    parser.add_argument("--wipe-data", action="store_true",
                        help="删除数据目录全部内容")
    parser.add_argument("--confirm-wipe", action="store_true",
                        help="擦除的显式确认参数，缺省拒绝执行")
    parser.add_argument("--data-dir",
                        help="数据目录（开发态必填；frozen 缺省取 exe 旁 data/）")
    args = parser.parse_args(argv)

    if args.pre_upgrade_backup == args.wipe_data:  # 同给或都不给都是误用
        parser.print_usage(sys.stderr if sys.stderr is not None else None)
        return EXIT_BAD_USAGE
    data_dir = Path(args.data_dir) if args.data_dir else default_data_dir()

    try:
        if args.wipe_data:
            result = wipe_data(data_dir, confirm=bool(args.confirm_wipe))
        else:
            result = pre_upgrade_backup(data_dir)
    except MaintenanceError as exc:
        _emit({"status": "error", "error": exc.code}, error=True)
        return exc.exit_code
    _emit(result)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
