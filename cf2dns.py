#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 自动化更新与健康巡检

把「能真正连通你站点的 Cloudflare 边缘 IP」按 DNSPod 线路写成 A 记录，并持续巡检。

设计要点（相比第一版）：
  1. 健康预检探静态的 /robots.txt，接受 2xx/3xx —— 探 `/` 会把站点自己的一次
     404 当成「全部节点都坏了」。
  2. 每条线路写 2 条 A 记录（DNSPod 免费版同线路上限），单 IP 被假墙不至于全灭。
  3. 所有候选（含兜底）都验不过时判定为「源站问题」，本轮不动 DNS 并告警。
  4. 写入前校验 IP 落在 Cloudflare 公布段内，防数据源污染写出不可解析的记录。
  5. 先建后删：新记录建立成功后才清理旧记录/旧 CNAME，避免中途失败留下空记录。
  6. 失败 IP 进 6h 黑名单；只有「本轮有候选通过」时才登记，避免站点故障污染黑名单。
  7. 稳定优先：仍然健康的现有 IP 一律保留；只有失效的才立即替换，缺额才补。
     想换掉健康的 IP 必须「满 rotate_after 时长」且「候选快 rotate_gain_ms 以上」。
  8. D1 租约：VPS/GHA 写 DNS 前先 acquire；心跳失败不写，避免主备同时改解析。
  9. 单实例锁 + 状态/黑名单落盘 + Telegram 告警（token 放独立 env 文件，路径可配）。

用法：
  cf2dns.py --dry-run            # 只探测与决策，不写 DNS、不告警、不落盘
  cf2dns.py                      # 正常同步（建议 cron 每 30 分钟）
  cf2dns.py --config /path.json  # 指定配置文件

密钥永远不写在配置模板里：config.json 只放腾讯云密钥，权限 600；
Telegram token 放 env 文件（默认 /etc/cf2dns/telegram.env，见 config 的 telegram_env_file）。
"""

import argparse
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.environ.get("CF2DNS_CONFIG") or os.path.join(SCRIPT_DIR, "config.json")
LOG_FILE = os.environ.get("CF2DNS_LOG", "/var/log/cf2dns.log")

STATE_DIR = os.environ.get("CF2DNS_STATE_DIR", "/var/lib/cf2dns")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
BLACKLIST_FILE = os.path.join(STATE_DIR, "blacklist.json")
CF_RANGES_CACHE = os.path.join(STATE_DIR, "cf-ips-v4.txt")
LOCK_FILE = os.environ.get("CF2DNS_LOCK", "/run/cf2dns.lock")

DEFAULT_TG_ENV = "/etc/cf2dns/telegram.env"
HOSTMONIT_URL = "https://api.hostmonit.com/get_optimization_ip"
ADDRESSES_API = "https://addressesapi.090227.xyz/CloudFlareYes"
CF_RANGES_URL = "https://api.cloudflare.com/client/v4/ips"  # JSON，给程序用的
CF_RANGES_URL_TEXT = "https://www.cloudflare.com/ips-v4"  # 备用：纯文本列表
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# SSLContext 可跨线程复用；每个 IP 新建一次会白白重复加载证书链。
TLS_CONTEXT = ssl.create_default_context()

# 线路 -> 优选池。境外/教育网用电信池，广电用移动池，搜索引擎用官方固定 Anycast。
DEFAULT_LINES = {
    "默认": {"pool": None, "records": 1},
    "电信": {"pool": "CT", "records": 2},
    "联通": {"pool": "CU", "records": 2},
    "移动": {"pool": "CM", "records": 2},
    "境外": {"pool": "CT", "records": 2},
    "教育网": {"pool": "CT", "records": 2},
    "广电": {"pool": "CM", "records": 2},
    "搜索引擎": {"pool": None, "records": 1},
}
DEFAULT_FALLBACKS = {
    "电信": "162.159.192.1",
    "联通": "104.17.1.1",
    "移动": "104.19.1.1",
    "境外": "162.159.192.1",
    "教育网": "162.159.192.1",
    "广电": "104.19.1.1",
    "搜索引擎": "104.21.81.143",
}

# 最后一道保险：拉不到官方段列表时用它（2026-11 从 api.cloudflare.com/client/v4/ips 抄下）
FALLBACK_RANGES = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

def setup_logging():
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(LOG_FILE, encoding="utf-8"))
    except OSError as e:  # 本地调试时没有 /var/log 写权限，退化为只打 stdout
        print(f"日志文件不可写（{e}），仅输出到 stdout", file=sys.stderr)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


setup_logging()
log = logging.getLogger("cf2dns")


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def load_config():
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        # GHA 用 example + 环境变量覆盖是显式支持的；普通 VPS 缺 config 时不能
        # 悄悄拿 example 的占位域名/密钥跑。需要 example 必须显式给环境变量。
        if not os.environ.get("TC_SECRET_ID") and os.environ.get("CF2DNS_ALLOW_EXAMPLE") != "1":
            log.error("配置文件不存在: %s（拒绝回退 example；如确需请设 CF2DNS_ALLOW_EXAMPLE=1）", CONFIG_FILE)
            sys.exit(1)
        example = os.path.join(SCRIPT_DIR, "config.example.json")
        if os.path.exists(example):
            with open(example, "r", encoding="utf-8") as f:
                config = json.load(f)
        else:
            log.error("配置文件不存在: %s", CONFIG_FILE)
            sys.exit(1)

    # 允许系统环境变量覆盖配置（特别方便 GitHub Actions 与容器化环境）
    if os.environ.get("TC_SECRET_ID"):
        config["secret_id"] = os.environ["TC_SECRET_ID"]
    if os.environ.get("TC_SECRET_KEY"):
        config["secret_key"] = os.environ["TC_SECRET_KEY"]
    if os.environ.get("DOMAIN"):
        config["domain"] = os.environ["DOMAIN"]
    if os.environ.get("CF2DNS_HEARTBEAT_URL"):
        config["heartbeat_url"] = os.environ["CF2DNS_HEARTBEAT_URL"]
    if os.environ.get("CF2DNS_HEARTBEAT_TOKEN"):
        config["heartbeat_token"] = os.environ["CF2DNS_HEARTBEAT_TOKEN"]

    config.setdefault("lines", DEFAULT_LINES)
    config.setdefault("fallback_ips", DEFAULT_FALLBACKS)
    config.setdefault("ttl", 600)
    config.setdefault("probe", {})
    config["probe"].setdefault("path", "/robots.txt")
    config["probe"].setdefault("timeout", 3)
    config["probe"].setdefault("attempts", 2)
    config.setdefault("switch", {})
    config["switch"].setdefault("rotate_after", 21600)  # 6h 才允许换掉健康 IP
    config["switch"].setdefault("rotate_gain_ms", 25)  # 且必须快 25ms 以上
    config.setdefault("blacklist_ttl", 21600)  # 6h 冷却，够长压住抖动、够短等它自愈
    config.setdefault("blacklist_fail_threshold", 2)
    config.setdefault("cf_ranges_ttl", 86400)
    config.setdefault("alert_cooldown", 21600)
    config.setdefault("lease_seconds", LEASE_SECONDS)
    config.setdefault("subdomain", "@")
    config.setdefault("telegram_env_file", DEFAULT_TG_ENV)
    config.setdefault("hostmonit_key", "o1zrmHAF")  # 上游公开 key，可换成自己的
    config.setdefault("heartbeat_url", "https://skcso.com/api/cf2dns")
    return config


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def http_json(url, payload=None, headers=None, timeout=8):
    data = None
    hdrs = {"User-Agent": "cf2dns/3.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_telegram(text, config):
    """推 Telegram 告警：优先读环境变量，其次从配置的 env 文件读 TG_TOKEN / TG_CHAT。"""
    env = {}
    env_file = config.get("telegram_env_file") or DEFAULT_TG_ENV
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
        except Exception as e:
            log.warning("读不到 Telegram 配置 %s: %s", env_file, e)

    token = os.environ.get("TG_TOKEN") or env.get("TG_TOKEN")
    chat = os.environ.get("TG_CHAT") or env.get("TG_CHAT")
    if not token or not chat:
        log.info("未配置 Telegram Token/Chat，跳过告警")
        return False
    try:
        body = urllib.parse.urlencode(
            {"chat_id": chat, "text": text, "disable_web_page_preview": "true"}
        ).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=body
        )
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception as e:
        # Telegram 的错误信息里可能带 bot token；只记录类型，别把 token 写进日志。
        log.warning("Telegram 告警发送失败: %s", type(e).__name__)
        return False


LEASE_SECONDS = 90 * 60


def post_heartbeat(config, payload):
    """POST 到 D1 心跳端点。返回解析后的 JSON；失败返回 None（调用方决定是否继续）。"""
    url = config.get("heartbeat_url")
    token = config.get("heartbeat_token")
    if not url or not token:
        log.info("未配置 heartbeat_url 或 heartbeat_token，跳过心跳")
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": f"cf2dns/{payload.get('node_id', 'vps')}",
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data
            log.warning("心跳返回失败: %s", data)
    except Exception as e:
        log.warning("心跳上报异常: %s", e)
    return None


def report_heartbeat(
    config,
    decisions=None,
    node_id="vps",
    status="ok",
    message="",
    *,
    op="heartbeat",
    lease_seconds=None,
    state=None,
    include_lines=True,
):
    """上报心跳。op=heartbeat 只报活；op=acquire 才拿/续租约。"""
    payload = {
        "op": op,
        "node_id": node_id,
        "status": status,
        "message": message or f"由 {node_id} 调度完成",
    }
    if decisions is not None and include_lines:
        payload["lines"] = {
            str(k): list(v) if v else [] for k, v in decisions.items()
        }
    if lease_seconds is not None:
        payload["lease_seconds"] = int(lease_seconds)
    if state is not None:
        payload["state"] = state
    data = post_heartbeat(config, payload)
    if data:
        log.info("[%s] 心跳同步成功（%s）", node_id, status)
    return data


def fetch_heartbeat(config):
    """读取心跳。GHA 用 ?fresh=1 绕开可能存在的浏览器/CDN 短缓存。"""
    url = config.get("heartbeat_url")
    if not url:
        return None
    sep = "&" if "?" in url else "?"
    try:
        req = urllib.request.Request(
            f"{url}{sep}fresh=1",
            headers={"User-Agent": "cf2dns/failover"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        log.warning("读取心跳失败: %s", e)
        return None


def acquire_lease(config, node_id, *, status="starting", message="", lease_seconds=None):
    """拿/续主备租约；返回 API 的完整响应，失败返回 None。"""
    seconds = lease_seconds or int(config.get("lease_seconds", LEASE_SECONDS))
    data = report_heartbeat(
        config,
        None,
        node_id=node_id,
        status=status,
        message=message,
        op="acquire",
        lease_seconds=seconds,
        include_lines=False,
    )
    return data


def release_lease(config, node_id, *, status="released", message=""):
    data = report_heartbeat(
        config,
        None,
        node_id=node_id,
        status=status,
        message=message,
        op="release",
        include_lines=False,
    )
    return bool(data and data.get("released"))


def check_failover(config, node_id="gha"):
    """检查心跳与租约。

    返回 True 表示备机可以启动；False 表示不要动 DNS。

    关键安全规则：
      · 心跳接口不可达/返回异常时 fail-safe，不接管（避免主备同时写）；
      · 主 VPS 租约仍有效时，即使心跳 stale 也等租约过期；
      · VPS 恢复并报活后，GHA 主动 release，把租约交还。
    """
    data = fetch_heartbeat(config)
    if not data or not data.get("ok"):
        log.warning("心跳接口不可用或返回异常，备机不接管（避免主备双写）")
        return False

    is_stale = bool(data.get("is_stale", True))
    owner = str(data.get("owner") or "")
    last_node = str(data.get("node_id") or "")
    lease_active = bool(data.get("lease_active", False))

    if not is_stale and last_node == "vps":
        # VPS 已经恢复并报活；如果租约在 GHA 手里，主动交还，让下一轮 VPS 接管。
        if owner == "gha":
            release_lease(
                config,
                "gha",
                status="released",
                message="VPS 已恢复报活，GHA 交还租约",
            )
            log.info("[standby] VPS 已恢复，GHA 已交还租约")
        else:
            log.info("[standby] VPS 心跳正常（%s 秒前），备机退避", data.get("elapsed_seconds"))
        return False

    if owner == "vps" and lease_active:
        log.info("[standby] VPS 持有有效租约（剩余 %s 秒），备机等待", max(0, int((data.get("lease_until") or 0) / 1000 - time.time())))
        return False

    if not is_stale and owner != "gha":
        log.info("[standby] 主节点心跳正常（%s 秒前），备机退避", data.get("elapsed_seconds"))
        return False

    if owner == "gha":
        # 已经是 GHA 接管态：继续执行/续租；VPS 恢复的情况上面已经交还。
        log.warning("[failover] GHA 继续接管（VPS 心跳 %s）", "stale" if is_stale else "fresh")
        return True

    if not lease_active:
        log.warning(
            "[failover] VPS 心跳异常（%s 秒前）且无有效租约，GHA 尝试接管",
            data.get("elapsed_seconds"),
        )
        return True

    log.warning("[failover] 租约仍被其他节点持有（owner=%s），备机不接管", owner or "unknown")
    return False

def maybe_alert(config, state, dry_run, key, text):
    """同一 key 在 alert_cooldown 内只发一次。"""
    if dry_run:
        log.warning("[dry-run] 本应告警(%s): %s", key, text)
        return
    alerts = state.setdefault("alerts", {})
    now = time.time()
    if now - alerts.get(key, 0) < config["alert_cooldown"]:
        log.info("告警 %s 处于冷却期，跳过", key)
        return
    if send_telegram(text, config):
        alerts[key] = now
        log.info("已发送告警 %s", key)


# --------------------------------------------------------------------------
# DNSPod API (TC3-HMAC-SHA256)
# --------------------------------------------------------------------------
def call_dnspod_api(action, payload_dict, config):
    host = "dnspod.tencentcloudapi.com"
    service = "dnspod"
    payload = json.dumps(payload_dict)
    timestamp = int(time.time())
    date = time.strftime("%Y-%m-%d", time.gmtime(timestamp))

    canonical_headers = (
        "content-type:application/json; charset=utf-8\n"
        f"host:{host}\n"
        f"x-tc-action:{action.lower()}\n"
    )
    signed_headers = "content-type;host;x-tc-action"
    hashed_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
    )

    algorithm = "TC3-HMAC-SHA256"
    credential_scope = f"{date}/{service}/tc3_request"
    hashed_canonical_request = hashlib.sha256(
        canonical_request.encode("utf-8")
    ).hexdigest()
    string_to_sign = (
        f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"
    )

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    secret_date = sign(("TC3" + config["secret_key"]).encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(
        secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    headers = {
        "Authorization": (
            f"{algorithm} Credential={config['secret_id']}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": "2021-03-23",
    }
    req = urllib.request.Request(
        f"https://{host}", data=payload.encode("utf-8"), headers=headers
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if "Error" in res.get("Response", {}):
            err = res["Response"]["Error"]
            raise RuntimeError(f"DNSPod API 错误: {err.get('Code')} - {err.get('Message')}")
        return res.get("Response", {})


# --------------------------------------------------------------------------
# Cloudflare 段校验
# --------------------------------------------------------------------------
def fetch_cf_ranges_text():
    """先走 JSON 接口（不易被 WAF 拦），失败再退回纯文本列表。"""
    try:
        data = http_json(CF_RANGES_URL, headers={"User-Agent": BROWSER_UA}, timeout=10)
        cidrs = (data.get("result") or {}).get("ipv4_cidrs") or []
        if cidrs:
            return "\n".join(cidrs)
    except Exception as e:
        log.warning("Cloudflare /ips 接口拉取失败: %s", e)
    req = urllib.request.Request(
        CF_RANGES_URL_TEXT, headers={"User-Agent": BROWSER_UA}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8")


def cloudflare_networks(config):
    ttl = config["cf_ranges_ttl"]
    cached, mtime = None, 0.0
    if os.path.exists(CF_RANGES_CACHE):
        mtime = os.path.getmtime(CF_RANGES_CACHE)
        cached = CF_RANGES_CACHE
    if cached and time.time() - mtime < ttl:
        return parse_ranges(open(cached, encoding="utf-8").read())
    try:
        text = fetch_cf_ranges_text()
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(CF_RANGES_CACHE, "w", encoding="utf-8") as f:
            f.write(text)
        return parse_ranges(text)
    except Exception as e:
        log.warning("拉取 Cloudflare IP 段失败: %s", e)
        if cached:
            log.warning("改用缓存段列表（可能过期）")
            return parse_ranges(open(cached, encoding="utf-8").read())
        log.warning("退回内置段列表（仅 IPv4 常用段）")
        return parse_ranges("\n".join(FALLBACK_RANGES))


def parse_ranges(text):
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets or None


def in_cloudflare(ip, nets):
    if nets is None:
        return True  # 拿不到段列表时不做拦截，但会被上面记一句 warning
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


# --------------------------------------------------------------------------
# 健康预检
# --------------------------------------------------------------------------
def probe_ip(ip, host, path, timeout, attempts):
    """返回 (ok, 毫秒)。TLS 带真实 SNI，接受 2xx/3xx。"""
    best = None
    for _ in range(max(1, attempts)):
        started = time.time()
        try:
            raw = socket.create_connection((ip, 443), timeout=timeout)
            tls = TLS_CONTEXT.wrap_socket(raw, server_hostname=host)
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: CF2DNS-Validator/3.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            tls.sendall(req)
            status_line = tls.recv(64).decode("utf-8", errors="ignore").split("\r\n")[0]
            tls.close()
            ms = int((time.time() - started) * 1000)
            code = status_line.split(" ")[1] if " " in status_line else ""
            if code.startswith("2") or code.startswith("3"):
                best = ms
                break
        except Exception:
            continue
    return best is not None, best


def probe_many(ips, host, probe_cfg):
    """并发探测，返回 {ip: 毫秒}（只含通过的）。"""
    result = {}
    if not ips:
        return result
    with ThreadPoolExecutor(max_workers=min(8, len(ips))) as pool:
        futures = {
            pool.submit(
                probe_ip,
                ip,
                host,
                probe_cfg["path"],
                probe_cfg["timeout"],
                probe_cfg["attempts"],
            ): ip
            for ip in ips
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                ok, ms = future.result()
            except Exception:
                ok, ms = False, None
            if ok:
                result[ip] = ms
    return result


# --------------------------------------------------------------------------
# 候选池
# --------------------------------------------------------------------------
def fetch_pool(config):
    pool = {"CT": [], "CU": [], "CM": []}

    try:
        data = http_json(
            HOSTMONIT_URL,
            {"key": config.get("hostmonit_key", "o1zrmHAF")},
            timeout=8,
        )
        if data.get("code") == 200:
            info = data.get("info", {})
            for key in ("CT", "CU", "CM"):
                pool[key] = [item["ip"] for item in info.get(key, [])]
            log.info(
                "Hostmonit 池: 电信(%d) 联通(%d) 移动(%d)",
                len(pool["CT"]),
                len(pool["CU"]),
                len(pool["CM"]),
            )
    except Exception as e:
        log.warning("Hostmonit 拉取失败: %s", e)

    if not all(pool[k] for k in pool):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    ADDRESSES_API, headers={"User-Agent": "cf2dns/3.0"}
                ),
                timeout=8,
            ) as resp:
                lines = resp.read().decode("utf-8").splitlines()
            for line in lines:
                line = line.strip()
                part = line.split("#")[0].strip()
                if not part:
                    continue
                if "#CT" in line and part not in pool["CT"]:
                    pool["CT"].append(part)
                elif "#CU" in line and part not in pool["CU"]:
                    pool["CU"].append(part)
                elif "#CM" in line and part not in pool["CM"]:
                    pool["CM"].append(part)
            log.info("备用 AddressesAPI 已合并进池")
        except Exception as e:
            log.warning("备用 AddressesAPI 拉取失败: %s", e)

    for key in pool:
        pool[key] = list(dict.fromkeys(pool[key]))
    return pool


# --------------------------------------------------------------------------
# 线路决策
# --------------------------------------------------------------------------
def probe_cached_many(ips, host, probe_cfg, cache):
    """一次巡检内按 IP 缓存探测结果，避免同池被 电信/境外/教育网 重复探。"""
    if cache is None:
        return probe_many(ips, host, probe_cfg)
    unique = list(dict.fromkeys(ip for ip in ips if ip))
    missing = [ip for ip in unique if ip not in cache]
    if missing:
        results = probe_many(missing, host, probe_cfg)
        for ip in missing:
            cache[ip] = results.get(ip)
    return {ip: cache[ip] for ip in unique if cache.get(ip) is not None}


def probe_cached_one(ip, host, probe_cfg, cache):
    if cache is None:
        return probe_ip(
            ip,
            host,
            probe_cfg["path"],
            probe_cfg["timeout"],
            probe_cfg["attempts"],
        )
    if ip not in cache:
        ok, ms = probe_ip(
            ip,
            host,
            probe_cfg["path"],
            probe_cfg["timeout"],
            probe_cfg["attempts"],
        )
        cache[ip] = ms if ok else None
    ms = cache.get(ip)
    return ms is not None, ms


def decide_line(
    line,
    spec,
    config,
    pool,
    nets,
    blacklist,
    host,
    current,
    entry,
    *,
    allow_rotate=True,
    probe_cache=None,
):
    """决定该线路应有的 A 记录集合。

    返回 (targets | None, reason, mode, failed_ips)：
      mode = keep / fill / urgent / rotate / fallback / dead
    None 表示「本轮不改，保持现状」。

    稳定性优先：仍然健康的现有 IP 一律保留，只有「死掉的」「数量不足的」
    才会被替换或补足；想换掉一个健康的 IP 必须同时满足「满了 rotate_after」
    且「候选确实更快 rotate_gain_ms 以上」——随机轮换的候选池不会让记录抖动。

    allow_rotate=False 用于 GHA 接管和 VPS 刚恢复的第一轮：只保健康/补失效，
    不按境外机器视角轮换。
    """
    want = int(spec.get("records", 1))
    probe_cfg = config["probe"]
    now = time.time()

    if spec.get("pool") is None:
        cands = list(spec.get("fixed") or [])
        if not cands and config.get("default_ip"):
            cands = [config["default_ip"]]
        if not cands and config["fallback_ips"].get(line):
            cands = [config["fallback_ips"][line]]
        if not cands:
            return None, "固定线路没有配置 IP（default_ip / fixed / fallback），跳过", "dead", []
    else:
        cands = list(pool.get(spec["pool"]) or [])

    usable = [
        ip for ip in cands if ip and ip not in blacklist and in_cloudflare(ip, nets)
    ]

    cur_probe = probe_cached_many(list(current), host, probe_cfg, probe_cache)
    kept = [ip for ip in current if ip in cur_probe]
    dead = [ip for ip in current if ip not in cur_probe]
    fresh = probe_cached_many(
        [ip for ip in usable if ip not in current], host, probe_cfg, probe_cache
    )
    # 真正握不上手/非 2xx-3xx 的候选（不含「没被选中」的）
    failed = [ip for ip in usable if ip not in current and ip not in fresh]

    # 候选池本身的顺序来自 Hostmonit 的运营商视角；同池去重后按池内顺序补位，
    # 不按德国/美国探针的本地耗时重排，避免把运营商池里的低延迟候选排到后面。
    pool_order = {ip: idx for idx, ip in enumerate(cands)}
    ranked = sorted(
        fresh.items(),
        key=lambda kv: (pool_order.get(kv[0], 10 ** 9), kv[1], kv[0]),
    )

    targets = list(kept)
    mode = "urgent" if dead else "keep"

    # 1) 数量不足就补
    if len(targets) < want:
        for ip, _ms in ranked:
            if len(targets) >= want:
                break
            targets.append(ip)
            if not dead:
                mode = "fill"

    # 2) 一个健康的都没有：退兜底，兜底也不行就保持现状
    if not targets:
        fallback = config["fallback_ips"].get(line)
        if fallback:
            ok, ms = probe_cached_one(
                fallback,
                host,
                probe_cfg,
                probe_cache,
            )
            if ok:
                return (
                    [fallback],
                    f"候选全灭，降级兜底 {fallback}({ms}ms)",
                    "fallback",
                    failed + dead,
                )
        detail = "、".join(dead[:3]) if dead else "无"
        return (
            None,
            f"候选与兜底均探不通（现有记录 {detail}），保持现状",
            "dead",
            failed + dead,
        )

    # 3) 轮换：满龄 + 确实更快，才动健康的现有 IP
    rotate_after = config["switch"]["rotate_after"]
    rotate_gain = config["switch"]["rotate_gain_ms"]
    age = now - entry.get("last_change", 0)
    if allow_rotate and len(targets) >= want and ranked and age >= rotate_after:
        pool_best = ranked[0][1]
        cur_best = min(cur_probe.get(ip, 10 ** 9) for ip in targets)
        if pool_best + rotate_gain <= cur_best:
            rotated = [ip for ip, _ in ranked[:want]]
            for ip in targets:  # 候选不够时用仍然健康的现有记录补足，不缩容
                if len(rotated) >= want:
                    break
                if ip not in rotated:
                    rotated.append(ip)
            if sorted(rotated) != sorted(targets):
                return (
                    rotated,
                    f"轮换到更快节点（用了 {age / 3600:.1f}h，"
                    f"{cur_best}ms -> {pool_best}ms）",
                    "rotate",
                    failed,
                )

    detail = ", ".join(f"{ip}({cur_probe.get(ip) or fresh.get(ip)}ms)" for ip in targets)
    reason = f"{'替换失效节点，' if dead else ''}目标 {detail}"
    return targets, reason, mode, failed + dead


def apply_line(config, records, line, targets, ttl):
    """把某线路的 A 记录对齐到 targets：先建后改后缀删。

    只管理 Remark=cf2dns:auto 的记录。同线路只要有手工记录就整条跳过：
    宁可不优化，也不能把用户自己的 A/CNAME 改掉。
    """
    sub = config.get("subdomain", "@")
    line_records = [r for r in records if r.get("Line") == line and r.get("Type") == "A"]
    unmanaged = [r for r in line_records if r.get("Remark") != "cf2dns:auto"]
    if unmanaged:
        log.warning(
            "[%s] 存在未标记的 A 记录（%s），跳过该线路，避免动到手工配置",
            line,
            ", ".join(str(r.get("Value")) for r in unmanaged[:3]),
        )
        return False, "存在未标记记录，跳过"
    current = [r for r in line_records if r.get("Remark") == "cf2dns:auto"]
    cur_values = [r.get("Value") for r in current]
    if sorted(cur_values) == sorted(targets):
        return False, "一致"

    changed = False
    domain = config["domain"]

    # 1) 先补齐数量（绝不先删）
    missing = [ip for ip in targets if ip not in cur_values]
    while len(current) < len(targets) and missing:
        ip = missing.pop(0)
        call_dnspod_api(
            "CreateRecord",
            {
                "Domain": domain,
                "SubDomain": sub,
                "RecordType": "A",
                "RecordLine": line,
                "Value": ip,
                "TTL": ttl,
                "Remark": "cf2dns:auto",
            },
            config,
        )
        log.info("[%s] 新建 A 记录 -> %s", line, ip)
        changed = True
        current.append({"Value": ip, "RecordId": None})

    # 2) 数量够但值不对 -> 原地改
    cur_values = [r.get("Value") for r in current]
    for idx, rec in enumerate(current):
        if rec.get("Value") in targets or not rec.get("RecordId"):
            continue
        replacement = next((ip for ip in targets if ip not in cur_values), None)
        if not replacement:
            break
        call_dnspod_api(
            "ModifyRecord",
            {
                "Domain": domain,
                "RecordId": rec["RecordId"],
                "SubDomain": sub,
                "RecordType": "A",
                "RecordLine": line,
                "Value": replacement,
                "TTL": ttl,
                "Remark": "cf2dns:auto",
            },
            config,
        )
        log.info("[%s] 改 A 记录 %s -> %s", line, rec.get("Value"), replacement)
        rec["Value"] = replacement
        cur_values[idx] = replacement
        changed = True

    # 3) 最后删多余（且保证至少留一条在目标集合里）
    surplus = [
        r
        for r in current
        if r.get("RecordId") and r.get("Value") not in targets
    ]
    remaining = [r.get("Value") for r in current if r.get("Value") in targets]
    for rec in surplus:
        if not remaining:
            break
        call_dnspod_api(
            "DeleteRecord",
            {"Domain": domain, "RecordId": rec["RecordId"]},
            config,
        )
        log.info("[%s] 删除多余 A 记录 %s", line, rec.get("Value"))
        changed = True

    return changed, "已更新"


def cleanup_line_cnames(config, records, lines):
    """该线路上已有 A 记录后，才清理这条线路残留的 CNAME（先建后删）。"""
    domain = config["domain"]
    for line in lines:
        has_a = any(r.get("Line") == line and r.get("Type") == "A" for r in records)
        if not has_a:
            continue
        for rec in records:
            if rec.get("Line") != line or rec.get("Type") != "CNAME":
                continue
            if rec.get("Remark") != "cf2dns:auto":
                log.warning(
                    "[%s] 存在未标记的 CNAME %s，跳过清理",
                    line,
                    rec.get("Value"),
                )
                continue
            call_dnspod_api(
                "DeleteRecord",
                {"Domain": domain, "RecordId": rec.get("RecordId")},
                config,
            )
            log.info("[%s] 清理残留 CNAME %s", line, rec.get("Value"))


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def run_sync(config, dry_run=False, node_id="vps"):
    domain = config["domain"]
    host = config.get("probe_host") or domain
    ttl = config["ttl"]
    lines_cfg = config["lines"]

    state = load_json(STATE_FILE, {})
    blacklist = load_json(BLACKLIST_FILE, {})
    fails = state.setdefault("fails", {})
    now = time.time()

    expired = [ip for ip, exp in blacklist.items() if exp < now]
    for ip in expired:
        blacklist.pop(ip, None)
    if expired:
        log.info("黑名单过期 %d 条", len(expired))

    heartbeat_enabled = bool(config.get("heartbeat_url") and config.get("heartbeat_token"))
    recovering = False
    lease_acquired = False

    if not dry_run and heartbeat_enabled:
        pre = fetch_heartbeat(config)
        if node_id == "vps" and pre:
            recovering = pre.get("owner") == "gha" or pre.get("node_id") == "gha"

        lease = acquire_lease(
            config,
            node_id,
            status="starting",
            message=f"{node_id} 开始本轮巡检",
        )
        if not lease or not lease.get("acquired"):
            owner = (lease or {}).get("owner") or (pre or {}).get("owner") or "unknown"
            log.warning("[%s] 未获得租约（当前 owner=%s），本轮不写 DNS", node_id, owner)
            maybe_alert(
                config,
                state,
                dry_run,
                "lease-unavailable",
                f"cf2dns：{node_id} 未获得 D1 租约（当前 owner={owner}），本轮未改 DNS",
            )
            report_heartbeat(
                config,
                None,
                node_id=node_id,
                status="recovering" if node_id == "vps" else "standby",
                message=f"租约由 {owner} 持有，等待交还",
                include_lines=False,
            )
            if not dry_run:
                save_json(STATE_FILE, state)
            return 0

        lease_acquired = True
        if lease.get("previous_owner") == "gha":
            recovering = True
        log.info(
            "[%s] 已获得租约（generation=%s, previous_owner=%s）",
            node_id,
            lease.get("generation"),
            lease.get("previous_owner"),
        )
    elif not dry_run:
        if node_id != "vps":
            log.error("备机（%s）未配置 heartbeat_url/heartbeat_token，拒绝在无租约下写 DNS", node_id)
            return 1
        log.warning("未配置 heartbeat_url/heartbeat_token，跳过租约保护（单机模式）")

    # GHA 接管时禁止 rotate；VPS 刚从 GHA 收回来时也先保健康，避免主备视角来回翻。
    allow_rotate = node_id == "vps" and not recovering

    nets = cloudflare_networks(config)
    pool = fetch_pool(config)
    log.info("=== %s 优选巡检（%s） ===", domain, "dry-run" if dry_run else "live")

    records = call_dnspod_api("DescribeRecordList", {"Domain": domain}, config).get(
        "RecordList", []
    )
    sub = config.get("subdomain", "@")
    root = [r for r in records if r.get("Name") == sub]

    current = {}
    unmanaged_lines = {}
    for line in lines_cfg:
        line_records = [
            r for r in root if r.get("Line") == line and r.get("Type") == "A"
        ]
        unmanaged = [r for r in line_records if r.get("Remark") != "cf2dns:auto"]
        if unmanaged:
            unmanaged_lines[line] = unmanaged
        current[line] = sorted(
            r.get("Value")
            for r in line_records
            if r.get("Remark") == "cf2dns:auto"
        )

    line_state = state.setdefault("lines", {})
    decisions, modes, failed_ips = {}, {}, set()
    probe_cache = {}
    for line, spec in lines_cfg.items():
        entry = line_state.setdefault(line, {})
        if line in unmanaged_lines:
            decisions[line], modes[line] = None, "skip"
            log.warning(
                "[%s] 存在未标记的 A 记录（%s），整条线路跳过",
                line,
                ", ".join(str(r.get("Value")) for r in unmanaged_lines[line][:3]),
            )
            continue
        targets, reason, mode, failed = decide_line(
            line,
            spec,
            config,
            pool,
            nets,
            blacklist,
            host,
            current[line],
            entry,
            allow_rotate=allow_rotate,
            probe_cache=probe_cache,
        )
        decisions[line], modes[line] = targets, mode
        failed_ips.update(failed)
        log.info("[%s] %s", line, reason)

    skip_lines = [ln for ln, m in modes.items() if m == "skip"]
    if skip_lines:
        maybe_alert(
            config,
            state,
            dry_run,
            "unmanaged-" + "-".join(sorted(skip_lines)),
            f"cf2dns：{domain} 这些线路存在未标记记录，已跳过：{', '.join(skip_lines)}",
        )

    # 源站看门狗：所有真正探测的线路（含兜底）都探不通，多半是本站挂了，别把 DNS 也拆了。
    # 全部 skip 不算源站故障，只是没权限管这些线路。
    origin_down = not skip_lines and all(
        targets is None for targets in decisions.values()
    )
    if origin_down:
        maybe_alert(
            config,
            state,
            dry_run,
            "origin-down",
            f"cf2dns：{domain} 所有线路（含兜底）都探不通，疑似源站问题，本轮未改 DNS",
        )
        if not dry_run:
            save_json(STATE_FILE, state)
            if heartbeat_enabled:
                clean = {k: [] for k in decisions}
                report_heartbeat(
                    config,
                    clean,
                    node_id=node_id,
                    status="origin-down",
                    message="所有线路（含兜底）均探不通，疑似源站故障；未改 DNS",
                )
        return 0

    dead_lines = [ln for ln, tg in decisions.items() if tg is None and modes.get(ln) != "skip"]
    if dead_lines:
        maybe_alert(
            config,
            state,
            dry_run,
            "dead-" + "-".join(sorted(dead_lines)),
            f"cf2dns：{domain} 这些线路无可用节点、保持现状：{', '.join(dead_lines)}",
        )
    fallback_lines = [ln for ln, m in modes.items() if m == "fallback"]
    if fallback_lines:
        maybe_alert(
            config,
            state,
            dry_run,
            "fallback-" + "-".join(sorted(fallback_lines)),
            f"cf2dns：{domain} 这些线路已降级到兜底 IP：{', '.join(fallback_lines)}",
        )

    # 黑名单：恢复了就放出来；连续 N 轮探不通才拉黑，避免一次抖动误伤
    if not dry_run:
        for targets in decisions.values():
            for ip in targets or []:
                if blacklist.pop(ip, None) is not None:
                    log.info("%s 恢复，移出黑名单", ip)
                fails.pop(ip, None)
        any_pool_ok = any(
            modes.get(ln) in ("keep", "fill", "urgent", "rotate")
            for ln, spec in lines_cfg.items()
            if spec.get("pool")
        )
        if any_pool_ok:
            threshold = int(config["blacklist_fail_threshold"])
            for ip in failed_ips:
                if ip in blacklist:
                    continue
                count = int(fails.get(ip, [0, 0])[0]) + 1
                fails[ip] = [count, now]
                if count >= threshold:
                    blacklist[ip] = now + config["blacklist_ttl"]
                    fails.pop(ip, None)
                    log.info("拉黑 %s（连续 %d 轮探不通）", ip, count)
        for ip in [i for i, v in fails.items() if now - v[1] > 86400]:
            fails.pop(ip, None)
        for entry in line_state.values():
            entry.pop("pending", None)
            entry.pop("pending_count", None)
        log.info("黑名单 %d 条 / 待观察 %d 条", len(blacklist), len(fails))
        save_json(BLACKLIST_FILE, blacklist)

    changed_lines = []
    for line, targets in decisions.items():
        if not targets:
            continue
        if sorted(targets) == current[line]:
            log.info("[%s] 无需变更 %s", line, ",".join(current[line]))
            continue
        if dry_run:
            log.info(
                "[dry-run] [%s] %s -> %s（%s）",
                line,
                ",".join(current[line]) or "-",
                ",".join(sorted(targets)),
                modes[line],
            )
            continue
        changed, note = apply_line(config, root, line, targets, ttl)
        if changed:
            changed_lines.append(line)
            line_state.setdefault(line, {})["last_change"] = time.time()
            log.info(
                "[%s] 已切换 %s -> %s（%s）",
                line,
                ",".join(current[line]) or "-",
                ",".join(sorted(targets)),
                modes[line],
            )
        else:
            log.info("[%s] %s", line, note)

    if not dry_run and changed_lines:
        records = call_dnspod_api("DescribeRecordList", {"Domain": domain}, config).get(
            "RecordList", []
        )
        cleanup_line_cnames(
            config, [r for r in records if r.get("Name") == sub], changed_lines
        )

    want = config.get("www_cname")
    if not dry_run and want:
        www = [r for r in records if r.get("Name") == "www"]
        www_unmanaged = [r for r in www if r.get("Remark") != "cf2dns:auto"]
        if www_unmanaged:
            log.warning("www 存在未标记记录，跳过 CNAME 修正")
            maybe_alert(
                config,
                state,
                dry_run,
                "unmanaged-www",
                f"cf2dns：{domain} 的 www 存在未标记记录，已跳过 CNAME 修正",
            )
        else:
            www_auto = [r for r in www if r.get("Remark") == "cf2dns:auto"]
            if www_auto and not (
                www_auto[0].get("Type") == "CNAME"
                and www_auto[0].get("Value") == want
            ):
                call_dnspod_api(
                    "ModifyRecord",
                    {
                        "Domain": domain,
                        "RecordId": www_auto[0]["RecordId"],
                        "SubDomain": "www",
                        "RecordType": "CNAME",
                        "RecordLine": "默认",
                        "Value": want,
                        "TTL": ttl,
                        "Remark": "cf2dns:auto",
                    },
                    config,
                )
                log.info("www CNAME 已修正为 %s", want)
            elif not www:
                call_dnspod_api(
                    "CreateRecord",
                    {
                        "Domain": domain,
                        "SubDomain": "www",
                        "RecordType": "CNAME",
                        "RecordLine": "默认",
                        "Value": want,
                        "TTL": ttl,
                        "Remark": "cf2dns:auto",
                    },
                    config,
                )
                log.info("www CNAME 已新建 -> %s", want)

    status = "degraded" if dead_lines or fallback_lines or skip_lines else "ok"
    if not dry_run:
        if recovering:
            # 刚收回租约：给所有线路一个 6h 冷却，避免按 VPS 视角立刻翻回。
            for entry in line_state.values():
                entry["last_change"] = time.time()
            log.info("检测到从 GHA 收回租约：本轮禁止轮换，并为各线路设置 6h 冷却")
        save_json(STATE_FILE, state)
        clean_decisions = {k: list(v) if v else [] for k, v in decisions.items()}
        if heartbeat_enabled:
            report_heartbeat(
                config,
                clean_decisions,
                node_id=node_id,
                status=status,
                message=f"{node_id} 巡检完成，{len(changed_lines)} 条线路变更",
            )
        if node_id != "vps" and lease_acquired:
            send_telegram(
                f"🚨 [cf2dns 备机接管]\n"
                f"主机探针心跳超时，备机（{node_id}）已接管 {config['domain']} 的 DNS 优选调度！\n"
                f"已完成健康探测并刷新三网解析记录。",
                config,
            )

    log.info("=== 巡检完成（%s） ===", status)
    return 0

def ensure_state_dir():
    global STATE_DIR, STATE_FILE, BLACKLIST_FILE, CF_RANGES_CACHE
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except (PermissionError, OSError):
        STATE_DIR = os.path.join(SCRIPT_DIR, ".state")
        os.makedirs(STATE_DIR, exist_ok=True)
        STATE_FILE = os.path.join(STATE_DIR, "state.json")
        BLACKLIST_FILE = os.path.join(STATE_DIR, "blacklist.json")
        CF_RANGES_CACHE = os.path.join(STATE_DIR, "cf-ips-v4.txt")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 同步")
    parser.add_argument("--dry-run", action="store_true", help="只探测，不写 DNS")
    parser.add_argument("--config", help="配置文件路径（默认 <脚本目录>/config.json）")
    parser.add_argument("--failover", action="store_true", help="以备机故障转移模式运行：先查心跳，超时才接管")
    parser.add_argument(
        "--node-id",
        default="vps",
        choices=("vps", "gha"),
        help="当前节点标识（默认 vps；GitHub Actions 必须传 gha）",
    )
    args = parser.parse_args()
    if args.failover and args.node_id == "vps":
        log.warning("--failover 未指定 --node-id gha，自动按 gha 运行，避免冒充主力")
        args.node_id = "gha"

    if args.config:
        global CONFIG_FILE
        CONFIG_FILE = os.path.abspath(args.config)
    config = load_config()

    if args.failover:
        should_run = check_failover(config, node_id=args.node_id)
        if not should_run:
            return 0

    ensure_state_dir()
    try:
        lock = open(LOCK_FILE, "w")
    except (PermissionError, OSError):
        lock = open(os.path.join(STATE_DIR, "cf2dns.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.warning("上一轮仍在运行，本轮跳过")
        return 0

    try:
        return run_sync(config, dry_run=args.dry_run, node_id=args.node_id)
    except Exception:
        log.exception("巡检异常")
        state = load_json(STATE_FILE, {})
        maybe_alert(
            config,
            state,
            args.dry_run,
            "exception",
            f"cf2dns：{config['domain']} 巡检抛异常，见 /var/log/cf2dns.log",
        )
        if not args.dry_run:
            # 异常也要证明「探针还活着」，否则 90 分钟后会被备机误判失联。
            report_heartbeat(
                config,
                None,
                node_id=args.node_id,
                status="error",
                message="巡检异常，本轮未完成；保留当前租约",
                include_lines=False,
            )
            save_json(STATE_FILE, state)
        return 1


if __name__ == "__main__":
    sys.exit(main())
