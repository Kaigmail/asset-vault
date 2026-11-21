"""Spec-002 桌面外壳包。

只承载窗口、本地服务生命周期、单实例与维护 CLI；依赖方向单向
desktop/ → app/，app/ 永不反向依赖本包（宪法隔离，Spec-001 测试
环境不引入 pywebview/pythonnet）。
"""
