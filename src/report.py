"""
HTML 报告生成器
将 AuditResult 数据渲染为与原 server-audit.sh 相同风格的 HTML 报告
"""

from datetime import datetime


def safe(v, default="未知"):
    return v if v else default


# =============================================================================
# 各章节渲染函数
# =============================================================================

def section_basic(data, ip):
    d = data
    mem_pct = d.get("mem_pct", 0)
    load_warns = d.get("cpu_warnings", [])
    mem_warns = d.get("mem_warnings", [])

    warns = ""
    for w in load_warns + mem_warns:
        cls = "crit" if "CRIT" in w else "warn"
        warns += '<p class="{cls}">{w}</p>'.format(cls=cls, w=w)

    return """
<div class="section">
  <h2>一、系统基本信息</h2>
  <table>
    <tr><th>项目</th><th>值</th></tr>
    <tr><td>主机名</td><td>{hostname}</td></tr>
    <tr><td>本机IP</td><td>{local_ip}</td></tr>
    <tr><td>操作系统</td><td>{os_name}</td></tr>
    <tr><td>内核版本</td><td>{kernel}</td></tr>
    <tr><td>架构</td><td>{arch}</td></tr>
    <tr><td>运行时间</td><td>{uptime}</td></tr>
    <tr><td>负载</td><td>{load_avg}</td></tr>
    <tr><td>启动时间</td><td>{boot_time}</td></tr>
  </table>
  {warns}
  <h3>网络信息</h3>
  <pre class="code">{network_raw}</pre>
</div>""".format(
    hostname=safe(d.get("hostname")),
    local_ip=safe(d.get("local_ip", ip)),
    os_name=safe(d.get("os_name")),
    kernel=safe(d.get("kernel")),
    arch=safe(d.get("arch")),
    uptime=safe(d.get("uptime")),
    load_avg=safe(d.get("load_avg")),
    boot_time=safe(d.get("boot_time")),
    warns=safe(warns, ""),
    network_raw=safe(d.get("network_raw")),
)


def section_cpu(data):
    d = data
    cpu_warns = d.get("cpu_warnings", [])
    warns = ""
    for w in cpu_warns:
        cls = "crit" if "CRIT" in w else "warn"
        warns += '<p class="{cls}">{w}</p>'.format(cls=cls, w=w)

    sockets = safe(d.get("cpu_sockets", "1"))
    cores_per = safe(d.get("cpu_cores_per_socket", ""))
    cpu_detail = "路数/每路核数: {s}/{c}".format(s=sockets, c=cores_per) if cores_per else ""

    return """
<div class="section">
  <h2>二、CPU 资源</h2>
  {warns}
  <table>
    <tr><th>项目</th><th>值</th></tr>
    <tr><td>型号</td><td>{model}</td></tr>
    <tr><td>路数/每路核数/逻辑核</td><td>{sockets} / {cores_per} / {cores}</td></tr>
  </table>
  <h3>实时 CPU</h3>
  <pre class="code">{usage}</pre>
</div>""".format(
    warns=safe(warns, ""),
    model=safe(d.get("cpu_model")),
    sockets=safe(d.get("cpu_sockets", "1")),
    cores_per=safe(d.get("cpu_cores_per_socket", "")),
    cores=safe(d.get("cpu_cores")),
    usage=safe(d.get("cpu_usage_raw")),
)


def section_mem(data):
    d = data
    mem_warns = d.get("mem_warnings", [])
    swap_warns = d.get("swap_warnings", [])

    warns = ""
    for w in mem_warns + swap_warns:
        cls = "crit" if "CRIT" in w else "warn"
        warns += '<p class="{cls}">{w}</p>'.format(cls=cls, w=w)

    mem_pct = d.get("mem_pct", 0)
    mem_cls = "crit" if mem_pct >= 85 else "warn" if mem_pct >= 70 else "ok"

    return """
<div class="section">
  <h2>三、内存资源</h2>
  {warns}
  <table>
    <tr><th>项目</th><th>值</th></tr>
    <tr><td>内存使用率</td><td class="{cls}">{pct}%</td></tr>
    <tr><td>已用/总量</td><td>{used}M / {total}M</td></tr>
    <tr><td>Swap 已用/总量</td><td>{swap_used}M / {swap_total}M</td></tr>
  </table>
  <h3>内存 TOP 10 进程</h3>
  <pre class="code">{mem_top}</pre>
  <h3>CPU TOP 10 进程</h3>
  <pre class="code">{cpu_top}</pre>
</div>""".format(
    warns=safe(warns, ""),
    cls=mem_cls,
    pct=mem_pct,
    used=d.get("mem_used_mb", 0),
    total=d.get("mem_total_mb", 0),
    swap_used=d.get("swap_used_mb", 0),
    swap_total=d.get("swap_total_mb", 0),
    mem_top=safe(d.get("mem_top")),
    cpu_top=safe(d.get("cpu_top")),
)


def section_disk(data):
    d = data
    warns = ""
    for w in d.get("disk_warnings", []):
        cls = "crit" if "CRIT" in w else "warn"
        warns += '<p class="{cls}">{w}</p>'.format(cls=cls, w=w)

    return """
<div class="section">
  <h2>四、磁盘与存储</h2>
  {warns}
  <h3>磁盘设备</h3>
  <pre class="code">{devices}</pre>
  <h3>分区使用情况</h3>
  <pre class="code">{raw}</pre>
  <h3>IOSTAT</h3>
  <pre class="code">{iostat}</pre>
</div>""".format(
    warns=safe(warns, ""),
    devices=safe(d.get("disk_devices")),
    raw=safe(d.get("disk_raw")),
    iostat=safe(d.get("iostat")),
)


def section_network(data):
    d = data
    conn = d.get("conn_stats", {})

    conn_rows = ""
    if conn:
        conn_rows = """
  <table>
    <tr><th>状态</th><th>数量</th></tr>
    <tr><td>总连接数</td><td>{total}</td></tr>
    <tr><td>ESTABLISHED</td><td>{established}</td></tr>
    <tr><td>SYN-WAIT</td><td>{syn_wait}</td></tr>
    <tr><td>TIME-WAIT</td><td>{time_wait}</td></tr>
    <tr><td>UDP</td><td>{udp}</td></tr>
  </table>""".format(
            total=safe(conn.get("total")),
            established=safe(conn.get("established")),
            syn_wait=safe(conn.get("syn_wait")),
            time_wait=safe(conn.get("time_wait")),
            udp=safe(conn.get("udp")),
        )

    return """
<div class="section">
  <h2>五、网络状态</h2>
  {conn_rows}
  <h3>监听端口 TOP30</h3>
  <pre class="code">{listen}</pre>
</div>""".format(
    conn_rows=safe(conn_rows, ""),
    listen=safe(d.get("listen_ports_raw")),
)


def section_apps(data):
    """六、应用业务清单"""
    d = data
    apps = d.get("apps", [])

    rows = ""
    for app in apps:
        ports_str = ", ".join(app.get("ports", []))
        procs = app.get("procs", [])
        proc_str = ", ".join(["{}/{}".format(pid, pn) for pid, pn in procs[:3]]) or "-"
        rows += """
    <tr>
      <td>{name}</td>
      <td>{app_type}</td>
      <td>{ports}</td>
      <td>{procs}</td>
    </tr>""".format(
            name=safe(app.get("app_name", "")),
            app_type=safe(app.get("app_type", "")),
            ports=ports_str,
            procs=proc_str,
        )

    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center;color:#9ca3af">无检测到应用</td></tr>'

    return """
<div class="section">
  <h2>六、应用业务清单</h2>
  <table>
    <tr><th>应用名</th><th>类型</th><th>端口</th><th>PID/进程名</th></tr>
    {rows}
  </table>
</div>""".format(rows=rows)


def section_docker(data):
    d = data
    if not d.get("docker_installed"):
        return """
<div class="section">
  <h2>七、Docker / 容器</h2>
  <p class="warn">&#9888; Docker 未安装</p>
</div>"""

    containers = d.get("docker_containers") or []
    perm = d.get("docker_has_perm", False)
    perm_warn = '<p class="warn">&#9888; Docker 已安装但当前用户无权限访问 daemon</p>' if not perm else ""

    rows = ""
    for c in containers[:20]:
        rows += """<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>""".format(
            safe(c.get("name")),
            safe(c.get("image")),
            safe(c.get("ports")),
            safe(c.get("status")),
        )
    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center;color:#9ca3af">无运行中容器</td></tr>'

    return """
<div class="section">
  <h2>七、Docker / 容器</h2>
  <table>
    <tr><th>版本</th><th>权限</th></tr>
    <tr><td>{version}</td><td>{perm}</td></tr>
  </table>
  {perm_warn}
  <h3>运行中容器</h3>
  <table>
    <tr><th>名称</th><th>镜像</th><th>端口</th><th>状态</th></tr>
    {rows}
  </table>
  <h3>本地镜像</h3>
  <pre class="code">{images}</pre>
</div>""".format(
    version=safe(d.get("docker_version")),
    perm="&#9989; 正常" if perm else "&#9888; 无权限",
    perm_warn=perm_warn,
    rows=rows,
    images=safe(d.get("docker_images")),
)


def section_cron(data):
    d = data
    return """
<div class="section">
  <h2>八、定时任务</h2>
  <h3>当前用户 Crontab</h3>
  <pre class="code">{cron}</pre>
  <h3>Root Crontab</h3>
  <pre class="code">{cron_root}</pre>
</div>""".format(
    cron=safe(d.get("cron")),
    cron_root=safe(d.get("cron_root")),
)


def section_user(data):
    d = data
    return """
<div class="section">
  <h2>九、用户与安全</h2>
  <h3>在线用户</h3>
  <pre class="code">{online}</pre>
  <h3>SELinux 状态</h3>
  <pre class="code">{selinux}</pre>
  <h3>SSH 配置摘要</h3>
  <pre class="code">{ssh_config}</pre>
</div>""".format(
    online=safe(d.get("online_users")),
    selinux=safe(d.get("selinux")),
    ssh_config=safe(d.get("ssh_config")),
)


def section_gpu(data):
    d = data
    if not d.get("gpu_nvidia"):
        gpu_vendor = d.get("gpu_vendor", "")
        gpu_model = d.get("gpu_model", "")
        if gpu_vendor or gpu_model:
            return """
<div class="section">
  <h2>十、GPU 配置</h2>
  <p class="warn">&#9888; 未检测到 NVIDIA 驱动，但检测到：{vendor} {model}</p>
</div>""".format(vendor=gpu_vendor, model=gpu_model)
        return """
<div class="section">
  <h2>十、GPU 配置</h2>
  <p class="warn">&#9888; 未检测到 NVIDIA GPU</p>
</div>"""

    return """
<div class="section">
  <h2>十、GPU 配置</h2>
  <table>
    <tr><th>项目</th><th>值</th></tr>
    <tr><td>GPU 数量</td><td>{count} 张</td></tr>
    <tr><td>GPU 型号</td><td>{model}</td></tr>
    <tr><td>显存总容量</td><td>{mem}</td></tr>
  </table>
  <h3>GPU 详细信息</h3>
  <pre class="code">{info}</pre>
</div>""".format(
    count=safe(d.get("gpu_count", "0")),
    model=safe(d.get("gpu_model")),
    mem=safe(d.get("gpu_mem")),
    info=safe(d.get("gpu_info")),
)


def section_summary(data):
    """十一、问题汇总"""
    warn_count = data.get("_warn_count", 0)
    crit_count = data.get("_crit_count", 0)
    all_warns = data.get("_all_warnings", [])

    items = ""
    for w in all_warns:
        cls = "crit" if "CRIT" in w else "warn"
        items += '<p class="{cls}">{w}</p>'.format(cls=cls, w=w)

    status = "&#9989; 未发现明显问题" if warn_count == 0 and crit_count == 0 else "&#9888; 存在需要关注的问题"

    return """
<div class="section">
  <h2>十一、问题汇总</h2>
  <div class="summary-cards">
    <div class="card">
      <div class="label">告警数</div>
      <div class="value warn">{warn}</div>
    </div>
    <div class="card">
      <div class="label">危险数</div>
      <div class="value crit">{crit}</div>
    </div>
  </div>
  <p>{status}</p>
  {items}
</div>""".format(
    warn=warn_count,
    crit=crit_count,
    status=status,
    items=safe(items, ""),
)


# =============================================================================
# HTML 模板
# =============================================================================

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
* {{ box-sizing: border-box; }}
body {{
  font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
  background: #f5f7fa;
  color: #1f2937;
  margin: 0; padding: 20px;
  line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white; padding: 30px 40px;
  border-radius: 12px; margin-bottom: 20px;
}}
.header h1 {{ margin: 0 0 10px 0; font-size: 24px; }}
.header .meta {{ opacity: 0.9; font-size: 14px; }}
.summary-cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 15px; margin-bottom: 20px;
}}
.card {{
  background: white; border-radius: 10px;
  padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}}
.card .label {{ font-size: 13px; color: #6b7280; margin-bottom: 8px; }}
.card .value {{ font-size: 24px; font-weight: 600; }}
.card.ok .value {{ color: #059669; }}
.card.warn .value {{ color: #d97706; }}
.card.crit .value {{ color: #dc2626; }}
.section {{
  background: white; border-radius: 10px;
  padding: 25px 30px; margin-bottom: 15px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}}
.section h2 {{
  margin: 0 0 15px 0; font-size: 18px;
  border-left: 4px solid #667eea; padding-left: 12px;
}}
.section h3 {{ margin: 20px 0 10px 0; font-size: 15px; color: #374151; }}
pre.code {{
  background: #1f2937; color: #e5e7eb;
  padding: 15px; border-radius: 8px;
  overflow-x: auto; font-size: 13px;
  line-height: 1.5;
  font-family: "SF Mono", Consolas, Monaco, monospace;
}}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
th {{ background: #f9fafb; font-weight: 600; }}
tr:hover {{ background: #f9fafb; }}
.footer {{ text-align: center; color: #9ca3af; font-size: 12px; padding: 20px 0; }}
p.warn {{ background: #fef3c7; color: #92400e; padding: 10px 15px; border-radius: 6px; margin: 8px 0; }}
p.crit {{ background: #fee2e2; color: #991b1b; padding: 10px 15px; border-radius: 6px; margin: 8px 0; }}
</style>
</head>
<body>
<div class="container">
{header}

{summary_cards}

{section_basic}
{section_cpu}
{section_mem}
{section_disk}
{section_network}
{section_apps}
{section_docker}
{section_cron}
{section_user}
{section_gpu}
{section_summary}

<div class="footer">
  服务器清点报告 &middot; WinAuditTool &middot; 生成于 {gen_time}
</div>
</div>
</body>
</html>
"""


# =============================================================================
# 入口函数
# =============================================================================

def generate_report(result, output_path: str = None) -> str:
    """
    将 AuditResult 渲染为 HTML 报告
    """
    from pathlib import Path

    d = result.data if result.data else {}
    ip = result.ip
    hostname = result.hostname
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 顶部摘要卡片
    mem_pct = d.get("mem_pct", 0)
    mem_cls = "crit" if mem_pct >= 85 else "warn" if mem_pct >= 70 else "ok"
    warn_cnt = d.get("_warn_count", 0)
    crit_cnt = d.get("_crit_count", 0)

    cards = """
  <div class="summary-cards">
    <div class="card">
      <div class="label">主机名</div>
      <div class="value" style="font-size:18px">{hostname}</div>
    </div>
    <div class="card">
      <div class="label">本机IP</div>
      <div class="value" style="font-size:18px">{ip}</div>
    </div>
    <div class="card">
      <div class="label">内存使用率</div>
      <div class="value {cls}">{pct}%</div>
    </div>
    <div class="card">
      <div class="label">Docker</div>
      <div class="value" style="font-size:18px">{docker}</div>
    </div>
    <div class="card">
      <div class="label">GPU</div>
      <div class="value" style="font-size:18px">{gpu}</div>
    </div>
    <div class="card warn">
      <div class="label">告警数</div>
      <div class="value">{warn}</div>
    </div>
    <div class="card crit">
      <div class="label">危险数</div>
      <div class="value">{crit}</div>
    </div>
  </div>""".format(
        hostname=safe(hostname),
        ip=safe(ip),
        cls=mem_cls,
        pct=mem_pct,
        docker='&#9989; 已安装' if d.get('docker_installed') else '&#10060; 未安装',
        gpu='&#9989; NVIDIA' if d.get('gpu_nvidia') else '&#10060; 无',
        warn=warn_cnt,
        crit=crit_cnt,
    )

    header = """
<div class="header">
  <h1>服务器清点报告 &middot; {hostname}</h1>
  <div class="meta">
    IP: {ip} &nbsp;|&nbsp; 采集时间: {now} &nbsp;|&nbsp; WinAuditTool v1.0
  </div>
</div>""".format(hostname=safe(hostname), ip=safe(ip), now=now)

    html = REPORT_TEMPLATE.format(
        title="服务器报告 - {} ({})".format(hostname, ip),
        header=header,
        summary_cards=cards,
        section_basic=section_basic(d, ip),
        section_cpu=section_cpu(d),
        section_mem=section_mem(d),
        section_disk=section_disk(d),
        section_network=section_network(d),
        section_apps=section_apps(d),
        section_docker=section_docker(d),
        section_cron=section_cron(d),
        section_user=section_user(d),
        section_gpu=section_gpu(d),
        section_summary=section_summary(d),
        gen_time=now,
    )

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html
