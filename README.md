# WinAuditTool

Windows 服务器信息采集工具，一键生成 HTML 报告。

![GitHub repo size](https://img.shields.io/github/repo-size/po123po111/win-audit-tool)
![GitHub](https://img.shields.io/github/license/po123po111/win-audit-tool)

## 功能

- 可视化管理服务器清单（增删改）
- 一键 SSH 批量采集（Linux 服务器）
- 生成与原 `server-audit.sh` 相同风格的 HTML 报告
- 支持 Dear PyGui GUI，无需浏览器

## 安装 EXE（推荐）

直接从 [Releases](https://github.com/po123po111/win-audit-tool/releases) 下载最新 `.exe` 文件，双击运行。

## 手动构建

```bash
pip install -r requirements.txt
python src/main.py
```

## 打包 EXE

```bash
pip install pyinstaller
pyinstaller WinAuditTool.spec --clean
```

EXE 输出在 `dist/WinAuditTool/`

## 报告预览

生成的 HTML 报告包含：
- 系统基本信息（主机名、IP、系统、内核、运行时间）
- CPU 资源
- 内存资源
- 磁盘与存储
- 网络配置
- Docker / 容器
- 进程 TOP
- 用户与安全
- 定时任务
- GPU 配置（NVIDIA）

## 截图

（待补充）

## License

MIT
