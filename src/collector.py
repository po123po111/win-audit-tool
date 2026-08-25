"""
服务器信息采集核心模块
通过 paramiko SSH 连接到远程 Linux 服务器，执行信息采集命令，
解析输出为结构化数据字典。
"""

import re
from typing import Dict, Any, Optional, Callable, List, Tuple
from dataclasses import dataclass


@dataclass
class AuditResult:
    """采集结果容器"""
    success: bool
    hostname: str = ""
    ip: str = ""
    error: str = ""
    data: Dict[str, Any] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}


# =============================================================================
# 公共端口 → 应用名映射表（与原 server-audit.sh 一致）
# =============================================================================
PORT_APP_MAP: List[Tuple[str, str, str]] = [
    ("22",   "SSH",              "远程登录"),
    ("25",   "SMTP",             "邮件服务"),
    ("53",   "DNS",              "域名解析"),
    ("80",   "HTTP",             "Web服务"),
    ("443",  "HTTPS",            "Web服务"),
    ("3306", "MySQL",            "数据库"),
    ("3307", "MySQL",            "数据库(改端口)"),
    ("33060","MySQL X",          "数据库协议"),
    ("5432", "PostgreSQL",       "数据库"),
    ("6379", "Redis",            "缓存"),
    ("27017","MongoDB",          "数据库"),
    ("9200", "Elasticsearch",    "搜索引擎"),
    ("9300", "Elasticsearch",    "节点通信"),
    ("5672", "RabbitMQ",         "消息队列"),
    ("15672","RabbitMQ管理",     "消息队列Web"),
    ("9092", "Kafka",            "消息队列"),
    ("2181", "ZooKeeper",       "协调服务"),
    ("11211","Memcached",        "缓存"),
    ("3000", "Grafana",          "监控面板"),
    ("9090", "Prometheus",       "监控"),
    ("8086", "InfluxDB",         "时序数据库"),
    ("8080", "Tomcat/Java Web",  "Java应用"),
    ("8443", "HTTPS(替代)",      "Web服务"),
    ("8888", "通用Web服务",      "Web应用"),
    ("5000", "Flask/Registry",   "Python应用/镜像仓库"),
    ("8000", "Web应用",          "Python/Node应用"),
    ("8009", "Web应用",          "Java AJP"),
    ("9994", "Web服务",          "通用"),
    ("5173", "Web服务",          "前端开发"),
    ("18000","NetBox",           "CMDB"),
    ("23306","MySQL",            "数据库(改端口)"),
    ("7725", "StarVPN",          "VPN"),
    ("7726", "StarVPN",          "VPN"),
    ("554",  "RTSP",             "流媒体"),
    ("22000","SSH",              "远程登录(改端口)"),
    ("20123","Web服务",          "通用"),
    ("20124","Web服务",          "通用"),
    ("20125","Web服务",          "通用"),
]

_PORT_MAP = {p: (n, t) for p, n, t in PORT_APP_MAP}


def get_app_name(port: str) -> Tuple[str, str]:
    """通过端口号查应用名和类型"""
    return _PORT_MAP.get(port, ("unknown", ""))


# =============================================================================
# 工具函数
# =============================================================================

def run_cmd(ssh, cmd: str) -> str:
    """执行远程命令并返回输出（60秒超时）"""
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if err and not out:
            return err.strip()
        return out.strip()
    except Exception as e:
        return f"[ERROR] {e}"


def get_local_ip(ssh) -> str:
    """获取服务器本机 IP（排除 docker/loopback）"""
    out = run_cmd(ssh, "hostname -I 2>/dev/null || hostname -i")
    for ip in out.split():
        if not ip.startswith("127.") and not ip.startswith("172.17."):
            return ip
    return out.split()[0] if out else "unknown"


def parse_free_m(output: str) -> Dict[str, int]:
    """解析 free -m 输出"""
    result = {}
    for line in output.strip().split("\n"):
        parts = line.split()
        if not parts:
            continue
        key = parts[0].rstrip(":")
        vals = parts[1:]
        if len(vals) >= 3:
            try:
                result[f"{key}_total"] = int(vals[0])
                result[f"{key}_used"] = int(vals[1])
                result[f"{key}_free"] = int(vals[2])
            except ValueError:
                pass
    return result


def parse_docker_ps(output: str) -> List[Dict[str, str]]:
    """解析 docker ps --format JSON Lines"""
    if not output.strip():
        return []
    result = []
    import json
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            result.append({
                "name":   item.get("Names", ""),
                "image":  item.get("Image", ""),
                "ports":  item.get("Ports", ""),
                "status": item.get("Status", ""),
                "state":  item.get("State", ""),
            })
        except Exception:
            parts = line.split()
            if len(parts) >= 4:
                result.append({
                    "name":   parts[0],
                    "image":  parts[1],
                    "ports":  parts[3] if len(parts) > 3 else "",
                    "status": " ".join(parts[4:]) if len(parts) > 4 else "",
                    "state":  "",
                })
    return result


def parse_listen_ports(output: str) -> List[Dict[str, str]]:
    """
    解析 ss -tlnp 输出，返回监听端口列表 + 进程信息
    格式: Local Address:Port   State   PID/Program
    """
    result = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or "State" in line or "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_addr = parts[3]
        port_match = re.search(r':(\d+)$', local_addr)
        port = port_match.group(1) if port_match else "?"
        pid = ""
        proc_name = ""
        # 从剩余字段提取 pid=xxx 或 name/pid
        rest = " ".join(parts[5:]) if len(parts) > 5 else ""
        pid_match = re.search(r'pid=(\d+)', rest)
        if pid_match:
            pid = pid_match.group(1)
        # 尝试提取进程名
        name_match = re.search(r'users:\(\("([^"]+)', rest)
        if name_match:
            proc_name = name_match.group(1)
        app_name, app_type = get_app_name(port)
        result.append({
            "port":      port,
            "proc_name": proc_name,
            "pid":       pid,
            "app_name":  app_name if proc_name == "unknown" else proc_name,
            "app_type":  app_type,
        })
    return result


def parse_conn_stats(output: str) -> Dict[str, int]:
    """解析 ss -s 输出，返回连接统计"""
    result = {"total": 0, "established": 0, "syn_wait": 0, "time_wait": 0,
              "close_wait": 0, "udp": 0}
    for line in output.strip().split("\n"):
        line = line.strip()
        if line.startswith("Total:"):
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "Total:" and i + 1 < len(parts):
                    try:
                        result["total"] = int(parts[i + 1])
                    except ValueError:
                        pass
        elif "ESTAB" in line:
            try:
                m = re.search(r'(\d+)', line.split("ESTAB")[-1].strip().split()[0])
                if m:
                    result["established"] = m.group(1)
            except (ValueError, IndexError):
                pass
        elif "SYN-WAIT" in line or "SYN-SENT" in line:
            try:
                m = re.search(r'(\d+)', line.split()[-1])
                if m:
                    result["syn_wait"] += int(m.group(1))
            except (ValueError, IndexError):
                pass
        elif "TIME-WAIT" in line:
            try:
                m = re.search(r'(\d+)', line.split("TIME-WAIT")[-1].strip().split()[0])
                if m:
                    result["time_wait"] = m.group(1)
            except (ValueError, IndexError):
                pass
        elif "UDP" in line and "UDPMUX" not in line:
            try:
                m = re.search(r'(\d+)', line.split("UDP")[-1].strip().split()[0])
                if m:
                    result["udp"] = m.group(1)
            except (ValueError, IndexError):
                pass
    return result


# =============================================================================
# 主采集函数
# =============================================================================

def collect_server(ssh,
                   hostname: str,
                   ip: str,
                   progress_callback: Optional[Callable] = None,
                   sudo_pass: str = "") -> AuditResult:
    """
    采集一台服务器的完整信息

    Args:
        ssh: 已连接的 paramiko.SSHClient
        hostname: 服务器名称
        ip: 服务器 IP
        progress_callback: 进度回调 (stage, pct, msg)
        sudo_pass: sudo 密码（可选）
    Returns:
        AuditResult 对象
    """
    result = AuditResult(success=False, hostname=hostname, ip=ip)
    data: Dict[str, Any] = {}
    warn_count = 0
    crit_count = 0

    def progress(stage: str, pct: int, msg: str):
        if progress_callback:
            progress_callback(stage, pct, msg)

    def add_warn(msg: str):
        nonlocal warn_count
        warn_count += 1
        return f"[WARN] {msg}"

    def add_crit(msg: str):
        nonlocal crit_count
        crit_count += 1
        return f"[CRIT] {msg}"

    try:
        # ---- 一、基本信息 ----
        progress("一、基本信息", 5, "采集系统信息...")
        os_release = run_cmd(ssh, "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        data["os_name"] = os_release or run_cmd(ssh, "uname -sr")
        data["hostname"] = run_cmd(ssh, "hostname")
        data["local_ip"] = get_local_ip(ssh)
        data["kernel"] = run_cmd(ssh, "uname -r")
        data["arch"] = run_cmd(ssh, "uname -m")
        data["boot_time"] = run_cmd(ssh, "uptime -s 2>/dev/null || who -b | awk '{print $3,$4}'")
        data["uptime"] = run_cmd(ssh, "uptime | awk -F'up ' '{print $2}' | cut -d, -f1")
        load_avg = run_cmd(ssh, "uptime | awk -F'load average: ' '{print $2}'")
        data["load_avg"] = load_avg

        # ---- 二、CPU ----
        progress("二、CPU", 18, "采集CPU信息...")
        data["cpu_cores"] = run_cmd(ssh, "nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo '?'")

        # CPU 型号
        cpu_model = run_cmd(ssh, "lscpu 2>/dev/null | grep -i 'model name' | head -1 | cut -d: -f2 | xargs")
        if not cpu_model:
            cpu_model = run_cmd(ssh, "grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs")
        cpu_sockets = run_cmd(ssh, "lscpu 2>/dev/null | grep -i '^Socket' | awk '{print $NF}'")
        cores_per_socket = run_cmd(ssh, "lscpu 2>/dev/null | grep -i 'Core(s) per socket' | awk '{print $NF}'")
        data["cpu_model"] = cpu_model
        data["cpu_sockets"] = cpu_sockets or "1"
        data["cpu_cores_per_socket"] = cores_per_socket or data["cpu_cores"]

        # 实时 CPU
        cpu_usage_raw = run_cmd(ssh, "top -bn1 2>/dev/null | grep 'Cpu(s)' | head -1")
        data["cpu_usage_raw"] = cpu_usage_raw

        # CPU 告警
        data["cpu_warnings"] = []
        cpu_cores = data["cpu_cores"]
        try:
            load1 = float(load_avg.split(",")[0].strip())
            cpu_cores_i = int(cpu_cores) if str(cpu_cores).isdigit() else 1
            ratio = load1 / cpu_cores_i if cpu_cores_i else 0
            if ratio >= 2:
                data["cpu_warnings"].append(add_crit(f"负载过高 (1min负载 {load1}, 核心数 {cpu_cores_i}, 比值 {ratio:.1f})"))
                crit_count += 1
            elif ratio >= 1:
                data["cpu_warnings"].append(add_warn(f"负载偏高 (1min负载 {load1}, 核心数 {cpu_cores_i}, 比值 {ratio:.1f})"))
                warn_count += 1
        except (ValueError, IndexError):
            pass

        # ---- 三、内存 ----
        progress("三、内存", 30, "采集内存信息...")
        mem_raw = run_cmd(ssh, "free -h")
        data["mem_raw"] = mem_raw

        mem_info = parse_free_m(run_cmd(ssh, "free -m"))
        data["mem_total_mb"] = mem_info.get("Mem_total", 0)
        data["mem_used_mb"] = mem_info.get("Mem_used", 0)
        data["mem_free_mb"] = mem_info.get("Mem_free", 0)
        data["mem_avail_mb"] = mem_info.get("Mem_available", mem_info.get("Mem_free", 0))

        mem_pct = 0
        if data["mem_total_mb"] > 0:
            mem_pct = int(data["mem_used_mb"] * 100 / data["mem_total_mb"])
        data["mem_pct"] = mem_pct

        data["mem_warnings"] = []
        if mem_pct >= 85:
            data["mem_warnings"].append(add_crit(f"内存使用率 {mem_pct}%"))
            crit_count += 1
        elif mem_pct >= 70:
            data["mem_warnings"].append(add_warn(f"内存使用率 {mem_pct}%"))
            warn_count += 1

        # Swap
        swap_info = parse_free_m(run_cmd(ssh, "free -m"))
        data["swap_total_mb"] = swap_info.get("Swap_total", 0)
        data["swap_used_mb"] = swap_info.get("Swap_used", 0)
        data["swap_warnings"] = []
        if data["swap_used_mb"] > 0 and data["swap_total_mb"] > 0:
            swap_pct = int(data["swap_used_mb"] * 100 / data["swap_total_mb"])
            data["swap_warnings"].append(add_warn(f"Swap 已使用 {data['swap_used_mb']}M / {data['swap_total_mb']}M，内存可能吃紧"))

        # 内存 TOP10
        data["mem_top"] = run_cmd(ssh, "ps aux --sort=-rss | head -12")

        # CPU TOP10
        data["cpu_top"] = run_cmd(ssh, "ps aux --sort=-%cpu | head -12")

        # ---- 四、磁盘 ----
        progress("四、磁盘", 45, "采集磁盘信息...")
        disk_devices = run_cmd(ssh, "lsblk -d -n -o NAME,SIZE,TYPE 2>/dev/null | grep disk || echo '?'")
        data["disk_devices"] = disk_devices
        disk_raw = run_cmd(ssh, "df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2")
        data["disk_raw"] = disk_raw

        # 磁盘告警
        data["disk_warnings"] = []
        for line in disk_raw.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 6:
                try:
                    avail = float(re.sub(r'[^\d.]', '', parts[3]))
                    pct_str = re.sub(r'%', '', parts[4])
                    pct = int(pct_str)
                    mounted = parts[5] if len(parts) > 5 else ""
                    if pct >= 90:
                        data["disk_warnings"].append(add_crit(f"{mounted} 使用率 {pct}%（严重）"))
                        crit_count += 1
                    elif pct >= 80:
                        data["disk_warnings"].append(add_warn(f"{mounted} 使用率 {pct}%"))
                        warn_count += 1
                except (ValueError, IndexError):
                    pass

        # IOSTAT
        data["iostat"] = run_cmd(ssh, "iostat -xz 1 2 2>/dev/null | tail -20 || echo 'iostat 不可用'")

        # ---- 五、网络状态 ----
        progress("五、网络状态", 58, "采集网络信息...")

        # 网络接口
        data["network_raw"] = run_cmd(ssh, "ip -br addr show 2>/dev/null || ifconfig 2>/dev/null")

        # 默认路由
        data["default_route"] = run_cmd(ssh, "ip route show default 2>/dev/null | awk '{print $3,$5,$7}'")

        # DNS
        data["dns_servers"] = run_cmd(ssh, "cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | head -3")

        # 监听端口 + 进程
        listen_out = run_cmd(ssh, "ss -tlnp 2>/dev/null")
        data["listen_ports_raw"] = listen_out
        data["listen_ports"] = parse_listen_ports(listen_out)

        # 活动连接统计（新增！）
        conn_stats_out = run_cmd(ssh, "ss -s 2>/dev/null")
        data["conn_stats"] = parse_conn_stats(conn_stats_out)
        data["conn_stats_raw"] = conn_stats_out

        # ---- 六、应用业务清单 ----
        progress("六、应用业务清单", 68, "采集应用业务...")

        # 按端口查应用
        apps = {}
        for entry in data["listen_ports"]:
            port = entry["port"]
            app_name = entry["app_name"]
            app_type = entry["app_type"]
            proc_name = entry["proc_name"]
            pid = entry["pid"]
            key = app_name if app_name != "unknown" else f"port_{port}"
            if key not in apps:
                apps[key] = {
                    "app_name": app_name,
                    "app_type": app_type,
                    "ports": [],
                    "procs": [],  # (pid, proc_name)
                }
            if port not in [p for p, _ in apps[key]["ports"]]:
                apps[key]["ports"].append(port)
            if pid and (pid, proc_name) not in apps[key]["procs"]:
                apps[key]["procs"].append((pid, proc_name))

        data["apps"] = [{"name": k, **v} for k, v in apps.items()]

        # ---- 七、Docker ----
        progress("七、Docker", 78, "采集Docker信息...")
        has_docker = run_cmd(ssh, "command -v docker 2>/dev/null && echo YES || echo NO")
        data["docker_installed"] = (has_docker == "YES")

        if has_docker == "YES":
            data["docker_version"] = run_cmd(ssh, "docker --version 2>/dev/null")
            can_run = run_cmd(ssh, "docker ps >/dev/null 2>&1 && echo YES || echo NO")
            data["docker_has_perm"] = (can_run == "YES")

            if can_run == "YES":
                out = run_cmd(ssh, "docker ps --format '{{json .}}' 2>/dev/null")
                data["docker_containers"] = parse_docker_ps(out)
                data["docker_images"] = run_cmd(ssh, "docker images --format '{{.Repository}}:{{.Tag}} ({{.Size}})' 2>/dev/null | head -20")
            else:
                # 无权限时检查服务状态
                data["docker_status"] = run_cmd(ssh, "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null | head -3")
                data["docker_containers"] = []
        else:
            data["docker_containers"] = []

        # ---- 八、定时任务 ----
        progress("八、定时任务", 85, "采集定时任务...")
        data["cron"] = run_cmd(ssh, "crontab -l 2>/dev/null || echo '无'")
        data["cron_root"] = run_cmd(ssh, "sudo crontab -l 2>/dev/null || echo '无'")

        # ---- 九、用户与安全 ----
        progress("九、用户与安全", 90, "采集用户信息...")
        data["online_users"] = run_cmd(ssh, "who")
        data["ssh_config"] = run_cmd(ssh, "cat /etc/ssh/sshd_config 2>/dev/null | grep -iE '^Port|^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication' | head -10")

        # SELinux
        data["selinux"] = run_cmd(ssh, "getenforce 2>/dev/null || sestatus 2>/dev/null | head -3 || echo '不可用'")

        # ---- 十、GPU ----
        progress("十、GPU", 95, "采集GPU信息...")
        has_nvidia = run_cmd(ssh, "command -v nvidia-smi 2>/dev/null && echo YES || echo NO")
        data["gpu_nvidia"] = (has_nvidia == "YES")

        if has_nvidia == "YES":
            data["gpu_count"] = run_cmd(ssh, "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l | tr -d ' '")
            data["gpu_model"] = run_cmd(ssh, "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | xargs")
            gpu_mem = run_cmd(ssh, "nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | awk '{sum+=$1} END {printf \"%.0f\", sum}'")
            try:
                gpu_mem_i = int(gpu_mem)
                data["gpu_mem"] = f"{gpu_mem_i / 1024:.0f} GB" if gpu_mem_i >= 1024 else f"{gpu_mem_i} MB"
            except ValueError:
                data["gpu_mem"] = gpu_mem
            data["gpu_info"] = run_cmd(ssh, "nvidia-smi --query-gpu=index,name,memory.total,memory.used,temperature.gpu,utilization.gpu,driver_version --format=csv 2>/dev/null")
        else:
            # lspci 兜底
            gpu_lspci = run_cmd(ssh, "lspci 2>/dev/null | grep -iE 'VGA|3D|Display' | head -5")
            if gpu_lspci and "nvidia" in gpu_lspci.lower():
                data["gpu_vendor"] = "NVIDIA (lspci)"
                data["gpu_model"] = gpu_lspci.split(": ", 1)[-1] if ": " in gpu_lspci else gpu_lspci
            elif gpu_lspci:
                data["gpu_vendor"] = "未知 (lspci)"
                data["gpu_model"] = gpu_lspci
            data["gpu_count"] = "0"

        # ---- 十一、问题汇总 ----
        data["_warn_count"] = warn_count
        data["_crit_count"] = crit_count
        data["_all_warnings"] = []
        for k, v in data.items():
            if k.endswith("_warnings") and isinstance(v, list):
                data["_all_warnings"].extend(v)

        result.data = data
        result.success = True
        progress("完成", 100, "采集完成")

    except Exception as e:
        result.error = str(e)

    return result
