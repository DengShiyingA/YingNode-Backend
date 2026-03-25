import requests
import base64
import json
import time
import subprocess
import os
import sys
from datetime import datetime
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler

# ==================== 配置区 ====================
SUB_URLS = [
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v2ray.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
]

OUTPUT_DIR = "./free_nodes"
XRAY_BIN = "./xray" if sys.platform != "win32" else "./xray.exe"
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_LATENCY = 300       # ping 延迟上限（毫秒）
SUPPORTED_PROTOCOLS = ("vmess://", "vless://", "trojan://", "ss://")

# 全局缓存
FREE_NODES_CACHE = None
LAST_FETCH_TIME = 0
CACHE_DURATION = 6 * 3600  # 6小时更新一次
# ================================================


def ping_ip(ip: str) -> int:
    try:
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "-w", "4000", ip]
        elif sys.platform == "darwin":
            # macOS: -W 单位是毫秒
            cmd = ["ping", "-c", "1", "-W", "4000", ip]
        else:
            # Linux: -W 单位是秒
            cmd = ["ping", "-c", "1", "-W", "4", ip]
        output = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            timeout=6,
        ).decode('utf-8', errors='ignore')
        if "time=" in output.lower():
            return int(''.join(filter(str.isdigit, output.split("time=")[-1].split("ms")[0])))
        return -1
    except Exception:
        return -1


def detect_protocol(config: str) -> str:
    """检测节点协议类型"""
    for proto in SUPPORTED_PROTOCOLS:
        if config.startswith(proto):
            return proto.replace("://", "")
    return ""


def extract_server(config: str) -> str:
    try:
        if config.startswith("vmess://"):
            data = json.loads(
                base64.b64decode(config[8:] + "==").decode(errors='ignore')
            )
            return data.get("add") or data.get("host") or ""
        elif config.startswith(("vless://", "trojan://")):
            return urlparse(config).hostname or ""
        elif config.startswith("ss://") and "@" in config:
            return config.split("@")[1].split(":")[0]
    except Exception:
        pass
    return ""


def fetch_free_nodes():
    global FREE_NODES_CACHE, LAST_FETCH_TIME
    print(f"[{datetime.now()}] 🚀 开始抓取免费节点...")

    # ---- 1. 抓取所有源 ----
    all_nodes = set()
    for url in SUB_URLS:
        try:
            resp = requests.get(url, timeout=20)
            raw_text = resp.text.strip()
            # 有些源是 base64 编码的订阅
            try:
                decoded = base64.b64decode(raw_text + "==").decode(errors='ignore')
                if "://" in decoded:
                    raw_text = decoded
            except Exception:
                pass
            nodes = [
                line.strip()
                for line in raw_text.splitlines()
                if line.strip() and any(line.strip().startswith(p) for p in SUPPORTED_PROTOCOLS)
            ]
            all_nodes.update(nodes)
            print(f"  ✅ {url.split('/')[-1]} 抓取 {len(nodes)} 条")
        except Exception as e:
            print(f"  ❌ {url.split('/')[-1]} 失败: {e}")

    # ---- 2. 按协议分组并过滤 ----
    valid_nodes = []
    for node in all_nodes:
        proto = detect_protocol(node)
        ip = extract_server(node)
        if proto and ip:
            valid_nodes.append((node, proto, ip))

    print(f"  📋 共 {len(all_nodes)} 条去重，{len(valid_nodes)} 条有效协议节点", flush=True)

    # ---- 3. Ping 可达性筛选 ----
    good_nodes = []
    node_details = []
    tested = 0
    test_list = valid_nodes[:800]
    total = len(test_list)

    # 去重 IP，避免同一 IP 重复 ping
    ip_latency_cache = {}

    for idx, (node, proto, ip) in enumerate(test_list, 1):
        if idx % 50 == 0 or idx == 1:
            print(f"  ⏳ 进度 {idx}/{total}  已通过: {len(good_nodes)} 个", flush=True)

        # 使用缓存避免重复 ping 同一 IP
        if ip in ip_latency_cache:
            latency = ip_latency_cache[ip]
        else:
            latency = ping_ip(ip)
            ip_latency_cache[ip] = latency
            tested += 1

        if latency == -1 or latency > MAX_LATENCY:
            continue

        good_nodes.append(node)
        node_details.append({
            "protocol": proto,
            "server": ip,
            "latency_ms": latency,
        })

    print(f"  📊 实际 ping 了 {tested} 个不同 IP", flush=True)

    # ---- 4. 按延迟排序 ----
    sorted_pairs = sorted(zip(good_nodes, node_details), key=lambda x: x[1]["latency_ms"])
    good_nodes = [p[0] for p in sorted_pairs]
    node_details = [p[1] for p in sorted_pairs]

    # ---- 5. 保存结果到内存 ----
    b64_content = base64.b64encode("\n".join(good_nodes).encode()).decode()

    # 协议统计
    proto_stats = {}
    for d in node_details:
        proto_stats[d["protocol"]] = proto_stats.get(d["protocol"], 0) + 1

    result = {
        "status": "success",
        "message": f"免费节点（ping ≤{MAX_LATENCY}ms，按延迟排序）",
        "subscription": b64_content,
        "nodes_count": len(good_nodes),
        "protocol_stats": proto_stats,
        "nodes_detail": node_details[:50],  # API 只返回前 50 条详情
        "expire_in_hours": 6,
        "updated_at": datetime.now().isoformat(),
    }

    FREE_NODES_CACHE = result
    LAST_FETCH_TIME = time.time()
    print(f"🎉 完成！可用节点: {len(good_nodes)} 个 | 协议分布: {proto_stats}")
    return result


# 定时任务（每6小时自动刷新）
def start_free_nodes_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        fetch_free_nodes,
        'interval',
        hours=6,
        id='xray_fast_nodes',
        replace_existing=True,
    )
    scheduler.start()
    print("⏰ 免费节点测速任务已启动（每6小时一次）")


if __name__ == "__main__":
    fetch_free_nodes()
