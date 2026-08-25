"""
服务器信息采集核心模块
通过 paramiko SSH 连接到远程 Linux 服务器，执行信息采集命令，
解析输出为结构化数据字典。
"""

import re
import socket
import json
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict


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


def detect_os(ssh) -> str:
    """检测远程服务器操作系统"""
    _, stdout, _ = ssh.exec_command("uname -s")
    os_name = stdout.read().decode().strip().lower()
    return "linux" if os_name == "linux" else "other"


def run_cmd(ssh, cmd: str) -> str:
    """执行远程命令并返回输出"""
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if err and not out:
            return err.strip()
        return out.strip()
    except Exception as e:
        return f"[ERROR] {e}"


def run_cmd_sudo(ssh, cmd: str, sudo_pass: str = "") -> str:
    """通过 sudo 执行命令（如果需要密码）"""
    full_cmd = f"echo '{sudo_pass}' | sudo -S {cmd}" if sudo_pass else f"sudo {cmd}"
    return run_cmd(ssh, full_cmd)


def parse_free_free(output: str) -> Dict[str, int]:
    """解析 free -m/-h 输出"""
    lines = output.strip().split("\n")
    result = {}
    for line in lines:
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


def parse_df_h(output: str) -> list:
    """解析 df -h 输出，返回磁盘分区列表"""
    lines = output.strip().split("\n")
    result = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            fs, size, used, avail, pct, mounted = parts[:6]
            try:
                avail_num = float(re.sub(r'[^\d.]', '', avail))
                pct_num = int(re.sub(r'%', '', pct))
                result.append({
                    "filesystem": fs,
                    "size": size,
                    "used": used,
                    "available": avail_num,
                    "use_pct": pct_num,
                    "mounted": mounted,
                })
            except (ValueError, IndexError):
                pass
    return result


def parse_ps_aux(output: str, top_n: int = 10) -> list:
    """解析 ps aux 输出，返回 top CPU/MEM 进程"""
    lines = output.strip().split("\n")
    result = []
    for line in lines[:top_n + 1]:
        parts = line.split()
        if len(parts) >= 11:
            try:
                result.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": float(parts[2]),
                    "mem": float(parts[3]),
                    "cmd": " ".join(parts[10:]),
                })
            except (ValueError, IndexError):
                pass
    return result


def parse_ss_tlnp(output: str) -> list:
    """解析 ss -tlnp 输出，返回监听端口+进程"""
    lines = output.strip().split("\n")
    result = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 5 and "LISTEN" in line:
            local_addr = parts[3]
            port_match = re.search(r':(\d+)$', local_addr)
            port = port_match.group(1) if port_match else "?"
            # 尝试从用户字段提取进程名
            proc_info = " ".join(parts[5:]) if len(parts) > 5 else ""
            pid_match = re.search(r'pid=(\d+)', proc_info)
            pid = pid_match.group(1) if pid_match else ""
            result.append({"port": port, "pid": pid, "info": proc_info})
    return result


def parse_docker_ps(output: str) -> list:
    """解析 docker ps --format JSON 输出"""
    if not output.strip():
        return []
    result = []
    try:
        # docker ps --format "{{json .}}" 输出 JSON Lines
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            import json as json_mod
            item = json_mod.loads(line)
            result.append({
                "name": item.get("Names", ""),
                "image": item.get("Image", ""),
                "ports": item.get("Ports", ""),
                "status": item.get("Status", ""),
                "state": item.get("State", ""),
            })
    except Exception:
        # 非 JSON 格式，逐行解析
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                result.append({
                    "name": parts[0],
                    "image": parts[1],
                    "ports": parts[3] if len(parts) > 3 else "",
                    "status": " ".join(parts[4:]) if len(parts) > 4 else "",
                    "state": "",
                })
    return result


def get_local_ip(ssh) -> str:
    """获取服务器本机 IP（排除 docker/loopback）"""
    out = run_cmd(ssh, "hostname -I 2>/dev/null || hostname -i")
    for ip in out.split():
        if not ip.startswith("127.") and not ip.startswith("172.17."):
            return ip
    return out.split()[0] if out else "unknown"


def collect_server(ssh, hostname: str, ip: str,
                   progress_callback: Optional[Callable] = None) -> AuditResult:
    """
    采集一台服务器的完整信息
    
    Args:
        ssh: 已连接的 paramiko.SSHClient
        hostname: 服务器名称（用于显示）
        ip: 服务器 IP
        progress_callback: 进度回调，接收 (stage: str, pct: int, message: str)
    
    Returns:
        AuditResult 对象
    """
    result = AuditResult(success=False, hostname=hostname, ip=ip)
    data = {}
    sudo_pass = ""  # 可从 inventory 配置传入

    def progress(stage: str, pct: int, msg: str):
        if progress_callback:
            progress_callback(stage, pct, msg)

    try:
        # ---- 基本信息 ----
        progress("基本信息", 5, "采集系统信息...")
        os_release = run_cmd(ssh, "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        data["os_name"] = os_release or run_cmd(ssh, "uname -sr")

        out = run_cmd(ssh, "hostname")
        data["hostname"] = out

        data["local_ip"] = get_local_ip(ssh)

        out = run_cmd(ssh, "uname -r")
        data["kernel"] = out

        out = run_cmd(ssh, "uname -m")
        data["arch"] = out

        out = run_cmd(ssh, "uptime -s 2>/dev/null || who -b | awk '{print $3,$4}'")
        data["boot_time"] = out

        out = run_cmd(ssh, "uptime | awk -F'up ' '{print $2}' | cut -d, -f1")
        data["uptime"] = out

        out = run_cmd(ssh, "uptime | awk -F'load average: ' '{print $2}'")
        data["load_avg"] = out

        # ---- CPU ----
        progress("CPU", 20, "采集CPU信息...")
        out = run_cmd(ssh, "lscpu 2>/dev/null | grep -E 'Model name|CPU\(s\)|Socket|Core' | head -5")
        data["cpu_raw"] = out

        out = run_cmd(ssh, "nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo '?'")
        data["cpu_cores"] = out

        out = run_cmd(ssh, "top -bn1 2>/dev/null | grep 'Cpu(s)' | head -1")
        data["cpu_usage"] = out

        # ---- 内存 ----
        progress("内存", 35, "采集内存信息...")
        out = run_cmd(ssh, "free -h")
        data["mem_raw"] = out

        out = run_cmd(ssh, "free -m | awk '/Mem:/{print $2,$3,$7}'")
        mem_parts = out.split()
        if len(mem_parts) >= 3:
            data["mem_total_mb"] = int(mem_parts[0])
            data["mem_used_mb"] = int(mem_parts[1])
            data["mem_avail_mb"] = int(mem_parts[2])

        out = run_cmd(ssh, "swapon -s 2>/dev/null | grep -v Filename | awk '{print $3}'")
        data["swap_total_mb"] = 0
        try:
            data["swap_total_mb"] = int(out) // 1024
        except ValueError:
            pass

        # ---- 磁盘 ----
        progress("磁盘", 50, "采集磁盘信息...")
        out = run_cmd(ssh, "df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2")
        data["disk_raw"] = out

        out = run_cmd(ssh, "lsblk -d -n -o NAME,SIZE,TYPE | grep disk 2>/dev/null || echo '?'")
        data["disk_devices"] = out

        # ---- 网络 ----
        progress("网络", 60, "采集网络信息...")
        out = run_cmd(ssh, "ip -br addr show 2>/dev/null || ifconfig 2>/dev/null")
        data["network_raw"] = out

        out = run_cmd(ssh, "ip route show default 2>/dev/null | awk '{print $3,$5,$7}' || route -n | grep UG | awk '{print $2,$5}'")
        data["default_route"] = out

        out = run_cmd(ssh, "cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | head -3")
        data["dns_servers"] = out

        out = run_cmd(ssh, "ss -tlnp 2>/dev/null | head -30")
        data["listen_ports"] = out

        # ---- Docker ----
        progress("Docker", 70, "采集Docker信息...")
        has_docker = run_cmd(ssh, "command -v docker 2>/dev/null && echo YES || echo NO")
        data["docker_installed"] = (has_docker == "YES")

        if has_docker == "YES":
            out = run_cmd(ssh, "docker --version 2>/dev/null")
            data["docker_version"] = out

            can_run = run_cmd(ssh, "docker ps >/dev/null 2>&1 && echo YES || echo NO")
            data["docker_has_perm"] = (can_run == "YES")

            if can_run == "YES":
                out = run_cmd(ssh, "docker ps --format '{{json .}}' 2>/dev/null")
                data["docker_containers"] = parse_docker_ps(out)

                out = run_cmd(ssh, "docker images --format '{{.Repository}}:{{.Tag}} ({{.Size}})' 2>/dev/null | head -20")
                data["docker_images"] = out
            else:
                # 无权限时：检查 docker 服务状态
                out = run_cmd(ssh, "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null | head -3")
                data["docker_status"] = out
                data["docker_containers"] = []

        # ---- 进程 TOP ----
        progress("进程", 80, "采集进程信息...")
        out = run_cmd(ssh, "ps aux --sort=-%cpu | head -12")
        data["top_cpu"] = out

        out = run_cmd(ssh, "ps aux --sort=-rss | head -12")
        data["top_mem"] = out

        # ---- 用户 ----
        progress("用户", 90, "采集用户信息...")
        out = run_cmd(ssh, "who")
        data["online_users"] = out

        out = run_cmd(ssh, "cat /etc/ssh/sshd_config 2>/dev/null | grep -iE '^Port|^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication' | head -10")
        data["ssh_config"] = out

        # ---- Crontab ----
        out = run_cmd(ssh, "crontab -l 2>/dev/null || echo '无'")
        data["cron"] = out

        # ---- GPU ----
        progress("GPU", 95, "采集GPU信息...")
        has_nvidia = run_cmd(ssh, "command -v nvidia-smi 2>/dev/null && echo YES || echo NO")
        data["gpu_nvidia"] = (has_nvidia == "YES")

        if has_nvidia == "YES":
            out = run_cmd(ssh, "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version --format=csv 2>/dev/null")
            data["gpu_info"] = out

        result.data = data
        result.success = True

        progress("完成", 100, "采集完成")

    except Exception as e:
        result.error = str(e)

    return result


def collect_local() -> AuditResult:
    """
    采集本机（Windows 运行 exe 时）信息
    优先用 paramiko 连接 localhost:22，否则用本地命令
    """
    result = AuditResult(success=False, hostname="localhost", ip="127.0.0.1")
    # 这里先留空，后续按需实现
    result.success = True
    return result
