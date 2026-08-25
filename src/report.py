"""
HTML 报告生成器
将 AuditResult 数据渲染为与原 server-audit.sh 相同风格的 HTML 报告
"""

from datetime import datetime
from pathlib import Path


def safe(v, default="未知"):
    """None 安全转字符串"""
    return v if v else default


def section_basic(data, ip):
    """基本信息章节"""
    d = data
    mem_pct = 0
    if d.get("mem_total_mb") and d.get("mem_used_mb"):
        mem_pct = int(d["mem_used_mb"] * 100 / d["mem_total_mb"])

    warn_blocks = ""
    if mem_pct >= 85:
        warn_blocks += '<p class="crit">&#128293; 内存使用率 {}%（严重）</p>'.format(mem_pct)
    elif mem_pct >= 70:
        warn_blocks += '<p class="warn">&#9888; 内存使用率 {}%（偏高）</p>'.format(mem_pct)

    return """
<div class="section">
  <h2>一、系统基本信息</h2>
  <table>
    <tr><th>项目</th><th>值</th></tr>
    <tr><td>主机名</td><td>{}</td></tr>
    <tr><td>本机IP</td><td>{}</td></tr>
    <tr><td>操作系统</td><td>{}</td></tr>
    <tr><td>内核版本</td><td>{}</td></tr>
    <tr><td>架构</td><td>{}</td></tr>
    <tr><td>运行时间</td><td>{}</td></tr>
    <tr><td>负载</td><td>{}</td></tr>
    <tr><td>启动时间</td><td>{}</td></tr>
  </table>
  {}
  <h3>网络信息</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(d.get('hostname')),
    safe(d.get('local_ip', ip)),
    safe(d.get('os_name')),
    safe(d.get('kernel')),
    safe(d.get('arch')),
    safe(d.get('uptime')),
    safe(d.get('load_avg')),
    safe(d.get('boot_time')),
    warn_blocks,
    safe(d.get('network_raw')),
)


def section_cpu(data):
    """CPU 章节"""
    d = data
    cpu_lines = safe(d.get('cpu_raw', ''))
    return """
<div class="section">
  <h2>二、CPU 资源</h2>
  <table>
    <tr><th>项目</th><th>值</th></tr>
    <tr><td>逻辑核数</td><td>{}</td></tr>
  </table>
  <h3>CPU 详情</h3>
  <pre class="code">{}</pre>
  <h3>实时 CPU 使用率</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(d.get('cpu_cores')),
    cpu_lines,
    safe(d.get('cpu_usage')),
)


def section_mem(data):
    """内存章节"""
    d = data
    mem_total = d.get('mem_total_mb', 0)
    mem_used = d.get('mem_used_mb', 0)
    mem_pct = int(mem_used * 100 / mem_total) if mem_total else 0

    warn = ""
    if mem_pct >= 85:
        warn = '<p class="crit">&#128293; 内存使用率 {}%（严重）</p>'.format(mem_pct)
    elif mem_pct >= 70:
        warn = '<p class="warn">&#9888; 内存使用率 {}%</p>'.format(mem_pct)

    return """
<div class="section">
  <h2>三、内存资源</h2>
  {}
  <pre class="code">{}</pre>
</div>""".format(warn, safe(d.get('mem_raw')))


def section_disk(data):
    """磁盘章节"""
    d = data
    return """
<div class="section">
  <h2>四、磁盘与存储</h2>
  <h3>磁盘设备</h3>
  <pre class="code">{}</pre>
  <h3>分区使用情况</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(d.get('disk_devices')),
    safe(d.get('disk_raw')),
)


def section_network(data):
    """网络章节"""
    d = data
    return """
<div class="section">
  <h2>五、网络配置</h2>
  <h3>默认路由</h3>
  <pre class="code">{}</pre>
  <h3>DNS</h3>
  <pre class="code">{}</pre>
  <h3>监听端口 TOP30</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(d.get('default_route')),
    safe(d.get('dns_servers')),
    safe(d.get('listen_ports')),
)


def section_docker(data):
    """Docker 章节"""
    d = data
    if not d.get('docker_installed'):
        return """
<div class="section">
  <h2>六、Docker / 容器</h2>
  <p class="warn">&#9888; Docker 未安装</p>
</div>"""

    containers = d.get('docker_containers') or []
    perm = d.get('docker_has_perm', False)
    perm_warn = '<p class="warn">&#9888; Docker 已安装但当前用户无权限访问 daemon</p>' if not perm else ''

    rows = ""
    for c in containers[:20]:
        rows += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            safe(c.get('name')),
            safe(c.get('image')),
            safe(c.get('ports')),
            safe(c.get('status')),
        )

    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center;color:#9ca3af">无运行中容器</td></tr>'

    return """
<div class="section">
  <h2>六、Docker / 容器</h2>
  <table>
    <tr><th>版本</th><th>权限</th></tr>
    <tr><td>{}</td><td>{}</td></tr>
  </table>
  {}
  <h3>运行中容器</h3>
  <table>
    <tr><th>名称</th><th>镜像</th><th>端口</th><th>状态</th></tr>
    {}
  </table>
  <h3>本地镜像</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(d.get('docker_version')),
    '&#9989; 正常' if perm else '&#9888; 无权限',
    perm_warn,
    rows,
    safe(d.get('docker_images')),
)


def section_process(data):
    """进程章节"""
    return """
<div class="section">
  <h2>七、进程 TOP</h2>
  <h3>CPU TOP</h3>
  <pre class="code">{}</pre>
  <h3>内存 TOP</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(data.get('top_cpu')),
    safe(data.get('top_mem')),
)


def section_user(data):
    """用户章节"""
    d = data
    return """
<div class="section">
  <h2>八、用户与安全</h2>
  <h3>在线用户</h3>
  <pre class="code">{}</pre>
  <h3>SSH 配置摘要</h3>
  <pre class="code">{}</pre>
</div>""".format(
    safe(d.get('online_users')),
    safe(d.get('ssh_config')),
)


def section_cron(data):
    """定时任务章节"""
    return """
<div class="section">
  <h2>九、定时任务</h2>
  <pre class="code">{}</pre>
</div>""".format(safe(data.get('cron')))


def section_gpu(data):
    """GPU 章节"""
    d = data
    if not d.get('gpu_nvidia'):
        return """
<div class="section">
  <h2>十、GPU 配置</h2>
  <p class="warn">&#9888; 未检测到 NVIDIA GPU</p>
</div>"""

    return """
<div class="section">
  <h2>十、GPU 配置</h2>
  <pre class="code">{}</pre>
</div>""".format(safe(d.get('gpu_info')))


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
{section_docker}
{section_process}
{section_user}
{section_cron}
{section_gpu}

<div class="footer">
  服务器清点报告 &middot; WinAuditTool &middot; 生成于 {gen_time}
</div>
</div>
</body>
</html>
"""


def generate_report(result, output_path: str = None) -> str:
    """
    将采集结果渲染为 HTML 报告
    """
    d = result.data if result.data else {}
    ip = result.ip
    hostname = result.hostname
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mem_pct = 0
    if d.get('mem_total_mb') and d.get('mem_used_mb'):
        mem_pct = int(d['mem_used_mb'] * 100 / d['mem_total_mb'])

    mem_cls = 'crit' if mem_pct >= 85 else 'warn' if mem_pct >= 70 else 'ok'

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
      <div class="value {mem_cls}">{mem_pct}%</div>
    </div>
    <div class="card">
      <div class="label">Docker</div>
      <div class="value" style="font-size:18px">{docker_status}</div>
    </div>
    <div class="card">
      <div class="label">GPU</div>
      <div class="value" style="font-size:18px">{gpu_status}</div>
    </div>
  </div>""".format(
        hostname=safe(hostname),
        ip=safe(ip),
        mem_pct=mem_pct,
        mem_cls=mem_cls,
        docker_status='&#9989; 已安装' if d.get('docker_installed') else '&#10060; 未安装',
        gpu_status='&#9989; NVIDIA' if d.get('gpu_nvidia') else '&#10060; 无',
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
        section_docker=section_docker(d),
        section_process=section_process(d),
        section_user=section_user(d),
        section_cron=section_cron(d),
        section_gpu=section_gpu(d),
        gen_time=now,
    )

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html
