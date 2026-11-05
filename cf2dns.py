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
  6. 失败 IP 进 24h 黑名单；只有「本轮有候选通过」时才登记，避免站点故障污染黑名单。
  7. 稳定优先：仍然健康的现有 IP 一律保留；只有失效的才立即替换，缺额才补。
     想换掉健康的 IP 必须「满 rotate_after 时长」且「候选快 rotate_gain_ms 以上」。
  8. 单实例锁 + 状态/黑名单落盘 + Telegram 告警（token 放独立 env 文件，路径可配）。

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
from concurrent.futures import ThreadPoolExecutor

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

# 线路 -> 优选池。境外线路用电信池（上游 cf2dns 的做法）。
DEFAULT_LINES = {
    "默认": {"pool": None, "records": 1},
    "电信": {"pool": "CT", "records": 2},
    "联通": {"pool": "CU", "records": 2},
    "移动": {"pool": "CM", "records": 2},
    "境外": {"pool": "CT", "records": 2},
}
DEFAULT_FALLBACKS = {
    "电信": "162.159.192.1",
    "联通": "104.17.1.1",
    "移动": "104.19.1.1",
    "境外": "162.159.192.1",
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
    if not os.path.exists(CONFIG_FILE):
        log.error("配置文件不存在: %s", CONFIG_FILE)
        sys.exit(1)
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)

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
    config.setdefault("subdomain", "@")
    config.setdefault("telegram_env_file", DEFAULT_TG_ENV)
    config.setdefault("hostmonit_key", "o1zrmHAF")  # 上游公开 key，可换成自己的
    # www_cname / default_ip 属于站点相关配置，故意不给默认值：不配就不动这几条记录
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
    """推 Telegram 告警：从配置的 env 文件读 TG_TOKEN / TG_CHAT。"""
    env = {}
    env_file = config.get("telegram_env_file") or DEFAULT_TG_ENV
    if not os.path.exists(env_file):
        log.info("未配置 Telegram env 文件（%s），跳过告警", env_file)
        return False
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
        return False
    token, chat = env.get("TG_TOKEN"), env.get("TG_CHAT")
    if not token or not chat:
        log.warning("Telegram 配置缺少 TG_TOKEN / TG_CHAT")
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
        log.warning("Telegram 告警发送失败: %s", e)
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
    ctx = ssl.create_default_context()
    best = None
    for _ in range(max(1, attempts)):
        started = time.time()
        try:
            raw = socket.create_connection((ip, 443), timeout=timeout)
            tls = ctx.wrap_socket(raw, server_hostname=host)
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
        for future, ip in futures.items():
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
def decide_line(line, spec, config, pool, nets, blacklist, host, current, entry):
    """决定该线路应有的 A 记录集合。

    返回 (targets | None, reason, mode, failed_ips)：
      mode = keep / fill / urgent / rotate / fallback / dead
    None 表示「本轮不改，保持现状」。

    稳定性优先：仍然健康的现有 IP 一律保留，只有「死掉的」「数量不足的」
    才会被替换或补足；想换掉一个健康的 IP 必须同时满足「满了 rotate_after」
    且「候选确实更快 rotate_gain_ms 以上」——随机轮换的候选池不会让记录抖动。
    """
    want = int(spec.get("records", 1))
    probe_cfg = config["probe"]
    now = time.time()

    if spec.get("pool") is None:
        cands = list(spec.get("fixed") or [])
        if not cands and config.get("default_ip"):
            cands = [config["default_ip"]]
        if not cands:
            return None, "固定线路没有配置 IP（default_ip / fixed），跳过", "dead", []
    else:
        cands = list(pool.get(spec["pool"]) or [])

    usable = [
        ip for ip in cands if ip and ip not in blacklist and in_cloudflare(ip, nets)
    ]

    cur_probe = probe_many(list(current), host, probe_cfg)
    kept = [ip for ip in current if ip in cur_probe]
    dead = [ip for ip in current if ip not in cur_probe]
    fresh = probe_many([ip for ip in usable if ip not in current], host, probe_cfg)
    # 真正握不上手/非 2xx-3xx 的候选（不含「没被选中」的）
    failed = [ip for ip in usable if ip not in current and ip not in fresh]

    targets = list(kept)
    mode = "urgent" if dead else "keep"

    # 1) 数量不足就补，按探测延迟从快到慢补
    if len(targets) < want:
        for ip, _ms in sorted(fresh.items(), key=lambda kv: (kv[1], kv[0])):
            if len(targets) >= want:
                break
            targets.append(ip)
            if not dead:
                mode = "fill"

    # 2) 一个健康的都没有：退兜底，兜底也不行就保持现状
    if not targets:
        fallback = config["fallback_ips"].get(line)
        if fallback:
            ok, ms = probe_ip(
                fallback,
                host,
                probe_cfg["path"],
                probe_cfg["timeout"],
                probe_cfg["attempts"],
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
    if len(targets) >= want and fresh and age >= rotate_after:
        ranked = sorted(fresh.items(), key=lambda kv: (kv[1], kv[0]))
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
    """把某线路的 A 记录对齐到 targets：先建后改后缀删。"""
    sub = config.get("subdomain", "@")
    current = [r for r in records if r.get("Line") == line and r.get("Type") == "A"]
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
            if rec.get("Line") == line and rec.get("Type") == "CNAME":
                call_dnspod_api(
                    "DeleteRecord",
                    {"Domain": domain, "RecordId": rec.get("RecordId")},
                    config,
                )
                log.info("[%s] 清理残留 CNAME %s", line, rec.get("Value"))


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def run_sync(config, dry_run=False):
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

    nets = cloudflare_networks(config)
    pool = fetch_pool(config)
    log.info("=== %s 优选巡检（%s） ===", domain, "dry-run" if dry_run else "live")

    records = call_dnspod_api("DescribeRecordList", {"Domain": domain}, config).get(
        "RecordList", []
    )
    sub = config.get("subdomain", "@")
    root = [r for r in records if r.get("Name") == sub]
    current = {
        line: sorted(
            r.get("Value")
            for r in root
            if r.get("Line") == line and r.get("Type") == "A"
        )
        for line in lines_cfg
    }

    line_state = state.setdefault("lines", {})
    decisions, modes, failed_ips = {}, {}, set()
    for line, spec in lines_cfg.items():
        entry = line_state.setdefault(line, {})
        targets, reason, mode, failed = decide_line(
            line, spec, config, pool, nets, blacklist, host, current[line], entry
        )
        decisions[line], modes[line] = targets, mode
        failed_ips.update(failed)
        log.info("[%s] %s", line, reason)

    # 源站看门狗：所有线路（含兜底）都探不通，多半是本站挂了，别把 DNS 也拆了
    if all(targets is None for targets in decisions.values()):
        maybe_alert(
            config,
            state,
            dry_run,
            "origin-down",
            f"cf2dns：{domain} 所有线路（含兜底）都探不通，疑似源站问题，本轮未改 DNS",
        )
        if not dry_run:
            save_json(STATE_FILE, state)
        return 0

    dead_lines = [ln for ln, tg in decisions.items() if tg is None]
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
        if www and not (
            www[0].get("Type") == "CNAME" and www[0].get("Value") == want
        ):
            call_dnspod_api(
                "ModifyRecord",
                {
                    "Domain": domain,
                    "RecordId": www[0]["RecordId"],
                    "SubDomain": "www",
                    "RecordType": "CNAME",
                    "RecordLine": "默认",
                    "Value": want,
                    "TTL": ttl,
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
                },
                config,
            )
            log.info("www CNAME 已新建 -> %s", want)

    if not dry_run:
        save_json(STATE_FILE, state)

    log.info("=== 巡检完成 ===")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 同步")
    parser.add_argument("--dry-run", action="store_true", help="只探测，不写 DNS")
    parser.add_argument("--config", help="配置文件路径（默认 <脚本目录>/config.json）")
    args = parser.parse_args()

    if args.config:
        global CONFIG_FILE
        CONFIG_FILE = os.path.abspath(args.config)
    config = load_config()

    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        lock = open(LOCK_FILE, "w")
    except PermissionError:
        lock = open("/tmp/cf2dns.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.warning("上一轮仍在运行，本轮跳过")
        return 0

    try:
        return run_sync(config, dry_run=args.dry_run)
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
            save_json(STATE_FILE, state)
        return 1


if __name__ == "__main__":
    sys.exit(main())
