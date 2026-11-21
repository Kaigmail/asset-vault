"""Flask 入口：起服务(127.0.0.1:8765) + 自动打开浏览器。"""

import sys
import threading
import webbrowser
from pathlib import Path

if getattr(sys, "frozen", False):
    # PyInstaller 打包运行时：资源目录是内部解压目录 _MEIPASS（入口脚本被放在其根下，
    # __file__ 的 parent.parent 是临时目录本身，不能用）；数据目录由 app.db 单独处理（exe 旁）。
    ROOT = Path(getattr(sys, "_MEIPASS"))
else:
    ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, send_from_directory  # noqa: E402

from app.api import bp as api_bp  # noqa: E402
from app import db, operations  # noqa: E402

STATIC_DIR = ROOT / "static"


def create_app(config=None, *, claim_process=True) -> Flask:
    # Probe before creating Flask; no startup schema/category/key writes.
    initial_state = db.probe_format()
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
    app.config.update(MAX_CONTENT_LENGTH=70 * 1024 * 1024,
                      VAULT_ALLOWED_ORIGINS=('http://localhost:8765', 'http://127.0.0.1:8765'),
                      # US3：可升级副本只来自安全环境显式配置；默认空=迁移功能关闭
                      VAULT_MIGRATION_SOURCES={})
    if config:
        app.config.update(config)
    manager = operations.for_vault(db.DB_PATH)
    # 浏览器开发入口维持「工厂即抢锁」的既有行为；桌面外壳由 single_instance
    # 先行抢锁并管理锁生命周期，此处传 claim_process=False 避免同一把锁抢两次。
    if claim_process:
        manager.claim_process()
    # 重启后从磁盘 meta 恢复冻结态：提交后核验失败的库继续拒绝普通写入
    if initial_state.state == 'maintenance_failed':
        manager.maintenance = True
    app.extensions['vault_operations'] = manager
    app.extensions['vault_initial_state'] = initial_state
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return send_from_directory(str(STATIC_DIR), "index.html")

    @app.errorhandler(404)
    @app.errorhandler(405)
    def _not_found_json(e):
        return jsonify({"error": "接口不存在或方法不支持", "code": 'route_not_found', "retryable": False}), e.code or 404

    return app


def main():
    app = create_app()
    url = "http://localhost:8765"
    print(f"Asset Vault is starting at {url}. Close this window to stop.")
    # 延迟 1 秒等服务起来后再打开浏览器
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        app.run(host="127.0.0.1", port=8765, debug=False, threaded=True)
    finally:
        app.extensions['vault_operations'].close()


if __name__ == "__main__":
    main()
