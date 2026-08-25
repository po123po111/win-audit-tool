"""
WinAuditTool - 服务器信息采集工具
入口文件，Dear PyGui 界面
"""

import os
import sys
import json
import threading
import traceback
from pathlib import Path

import dearpygui.dearpygui as dpg
import paramiko

from collector import collect_server, AuditResult
from report import generate_report

# ---- 配置路径 ----
BASE_DIR = Path(__file__).parent.parent  # 项目根目录
CONFIG_FILE = BASE_DIR / "servers.json"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# ---- 全局状态 ----
server_list = []  # [{ip, port, user, password, name}]
audit_threads = {}  # ip -> thread
audit_results = {}  # ip -> AuditResult
current_view_ip = None

# ---- Dear PyGui 初始化 ----
dpg.create_context()
dpg.create_viewport(title="WinAuditTool - 服务器信息采集", width=1200, height=800)

# ---- 配色主题 ----
with dpg.theme() as global_theme:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (40, 40, 60))
        dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (25, 25, 40))
        dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (60, 60, 100))
        dpg.add_theme_color(dpg.mvThemeCol_Button, (100, 100, 180))

# ---- 服务器列表回调 ----
def load_servers():
    global server_list
    if CONFIG_FILE.exists():
        try:
            server_list = json.loads(CONFIG_FILE.read_text())
        except Exception:
            server_list = []
    refresh_server_list()


def save_servers():
    CONFIG_FILE.write_text(json.dumps(server_list, ensure_ascii=False, indent=2))


def refresh_server_list():
    dpg.delete_item("server_list_table", children_only=True)
    for i, srv in enumerate(server_list):
        tag = srv["ip"]
        with dpg.table_row(parent="server_list_table"):
            dpg.add_text(srv.get("name", srv["ip"]))
            dpg.add_text(srv["ip"])
            dpg.add_text(str(srv.get("port", 22)))
            dpg.add_button(label="采集", callback=start_audit, user_data=tag)
            dpg.add_button(label="删除", callback=delete_server, user_data=tag)


# ---- 采集逻辑（线程中运行）----
def do_audit(ip):
    global audit_results

    srv = next((s for s in server_list if s["ip"] == ip), None)
    if not srv:
        return

    def progress(stage, pct, msg):
        dpg.set_value(f"progress_{ip}", pct / 100.0)
        dpg.configure_item(f"status_{ip}", label=f"{stage}... {pct}%")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        password = srv.get("password", "")
        port = int(srv.get("port", 22))

        ssh.connect(
            srv["ip"],
            port=port,
            username=srv["user"],
            password=password,
            timeout=30,
            banner_timeout=15,
            auth_timeout=15,
        )

        result = collect_server(ssh, srv.get("name", srv["ip"]), srv["ip"], progress_callback=progress)
        ssh.close()

    except Exception as e:
        result = AuditResult(success=False, hostname=srv.get("name", srv["ip"]), ip=srv["ip"], error=str(e))

    audit_results[ip] = result

    # 生成报告
    if result.success:
        outfile = REPORT_DIR / f"{ip}_{result.hostname}.html"
        generate_report(result, str(outfile))

    # 更新 UI
    dpg.configure_item(f"status_{ip}", label="完成" if result.success else f"失败: {result.error[:20]}")
    dpg.set_value(f"progress_{ip}", 1.0 if result.success else 0.0)
    dpg.configure_item(f"progress_{ip}", show=False)


def start_audit(sender, app_data, user_data):
    ip = user_data
    # 启动后台线程
    t = threading.Thread(target=do_audit, args=(ip,), daemon=True)
    audit_threads[ip] = t
    t.start()
    dpg.configure_item(f"status_{ip}", label="采集中...")
    dpg.configure_item(f"progress_{ip}", show=True)
    dpg.set_value(f"progress_{ip}", 0.0)


# ---- 回调 ----
def add_server(sender, app_data, user_data):
    dpg.show_item("add_server_popup")


def on_add_server(sender, app_data, user_data):
    name = dpg.get_value("input_name").strip()
    ip = dpg.get_value("input_ip").strip()
    port = dpg.get_value("input_port").strip() or "22"
    user = dpg.get_value("input_user").strip()
    password = dpg.get_value("input_pass").strip()

    if not ip or not user:
        return

    srv = {"name": name or ip, "ip": ip, "port": int(port), "user": user, "password": password}
    server_list.append(srv)
    save_servers()
    refresh_server_list()

    # 清空输入
    dpg.set_value("input_name", "")
    dpg.set_value("input_ip", "")
    dpg.set_value("input_port", "22")
    dpg.set_value("input_user", "")
    dpg.set_value("input_pass", "")
    dpg.hide_item("add_server_popup")


def delete_server(sender, app_data, user_data):
    global server_list
    server_list = [s for s in server_list if s["ip"] != user_data]
    save_servers()
    refresh_server_list()


def audit_all(sender, app_data, user_data):
    for srv in server_list:
        if srv["ip"] not in audit_threads:
            start_audit(None, None, srv["ip"])


def view_report(sender, app_data, user_data):
    ip = user_data
    result = audit_results.get(ip)
    if not result or not result.success:
        return
    outfile = REPORT_DIR / f"{ip}_{result.hostname}.html"
    if outfile.exists():
        import webbrowser
        webbrowser.open(f"file://{outfile}")


# ---- 主 UI 构建 ----
with dpg.window(tag="main_window", label="WinAuditTool"):
    # ---- 顶部工具栏 ----
    with dpg.group(horizontal=True):
        dpg.add_text("WinAuditTool", color=(150, 150, 255))
        dpg.add_spacer(width=50)
        dpg.add_button(label="+ 添加服务器", callback=add_server)
        dpg.add_button(label="全部采集", callback=audit_all)

    dpg.add_separator()

    # ---- 服务器列表 ----
    dpg.add_text("服务器列表", color=(180, 180, 220))
    dpg.add_spacer(height=5)

    with dpg.table(tag="server_list_table", header_row=True, row_background=True,
                   borders_innerV=True, borders_outer=True):
        dpg.add_table_column(label="名称")
        dpg.add_table_column(label="IP")
        dpg.add_table_column(label="端口")
        dpg.add_table_column(label="操作")
        dpg.add_table_column(label="状态")

    # 动态为每个服务器创建状态行
    for srv in server_list:
        ip = srv["ip"]
        with dpg.group(horizontal=True, tag=f"row_{ip}"):
            pass  # 状态行由采集时动态创建

    dpg.add_spacer(height=10)

    # ---- 报告预览区 ----
    dpg.add_separator()
    dpg.add_text("报告预览", color=(180, 180, 220))
    with dpg.child_window(height=400, autosize_x=True):
        dpg.add_text("请选择服务器并点击「采集」，完成后可查看报告",
                     wrap=700, color=(120, 120, 140))

# ---- 添加服务器弹窗 ----
with dpg.window(tag="add_server_popup", label="添加服务器",
                width=400, height=300, show=False, modal=True):
    dpg.add_text("添加新服务器")
    dpg.add_spacer(height=10)
    dpg.add_input_text(label="名称（选填）", tag="input_name", hint="如：测试服务器")
    dpg.add_input_text(label="IP *", tag="input_ip", hint="如：192.168.1.100")
    dpg.add_input_text(label="端口", tag="input_port", default_value="22", width=100)
    dpg.add_input_text(label="用户名 *", tag="input_user", hint="如：root")
    dpg.add_input_text(label="密码 *", tag="input_pass", password=True)
    dpg.add_spacer(height=10)
    with dpg.group(horizontal=True):
        dpg.add_button(label="确认添加", callback=on_add_server)
        dpg.add_button(label="取消", callback=lambda s, a, u: dpg.hide_item("add_server_popup"))

# ---- 视口设置 ----
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("main_window", True)

# ---- 启动时加载数据 ----
load_servers()

# ---- 主循环 ----
dpg.start_dearpygui()
dpg.destroy_context()
