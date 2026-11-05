# cf2dns

把「当前真的能连上你站点的 Cloudflare 边缘 IP」按 DNSPod 的线路写成 A 记录，每 30 分钟巡检一次。

适用场景：域名托管在 Cloudflare（Worker / Pages / 普通站点均可），NS 在 DNSPod（或任何支持按运营商分线路的 DNS 服务商），想让电信 / 联通 / 移动 / 境外访客各自解析到不同的边缘 IP。

只用 Python 标准库，单文件，无第三方依赖。

## 它做什么

```
Hostmonit 优选池 ──> 真实 TLS 探测 + Cloudflare 网段校验 ──> 保留健康的旧 IP / 补足 / 替换 ──> DNSPod 各线路 A 记录 ×2
```

每一步都是可选的显式行为，没有黑盒：

| 行为 | 说明 |
| --- | --- |
| 健康探测 | 带真实 SNI 的 TLS 握手 + `GET /robots.txt`，2xx/3xx 视为可用（默认 2 次尝试） |
| 每条线路 2 条 A 记录 | DNSPod 免费版同线路上限；单 IP 失效时还有第二条 |
| 稳定优先 | 仍然健康的现有 IP 一律保留；只替换失效的、只补足缺额 |
| 受控轮换 | 想换掉健康的 IP，必须距上次变更满 6 小时且候选快 25ms 以上 |
| 源站看门狗 | 所有线路（含兜底 IP）全都不通时，判定为源站故障，本轮不写 DNS，只告警 |
| 网段校验 | 候选 IP 必须落在 Cloudflare 公布的网段内（`api.cloudflare.com/client/v4/ips`，24h 缓存 + 内置兜底列表） |
| 先建后删 | 新增 → 原地修改 → 最后才删多余，避免出现「根域名没有任何 A 记录」的中间态 |
| 黑名单 | 连续 2 轮探测失败的 IP 进 6 小时黑名单；重新可用后自动释放 |
| 告警 | 降级到兜底、线路无节点、源站疑似故障、脚本异常，推 Telegram（可选） |
| 单实例锁 | 上一轮没跑完时本轮直接跳过 |

**为什么探 `/robots.txt` 而不是 `/`**：首页是渲染产物，站点自己的一次部署事故（比如只传上去一半静态资产）会让首页 404，而 `/robots.txt` 这类静态资产照常 200。探首页会把「本站出问题」误判成「所有节点都坏了」，进而把 DNS 全线降级。探静态资产能把这两件事解耦。

## 快速开始

```bash
git clone <this repo> && cd cf2dns
cp config.example.json config.json
chmod 600 config.json          # 里面是腾讯云密钥，别让其他用户读
$EDITOR config.json
python3 cf2dns.py --dry-run    # 只探测 + 打印决策，不写 DNS
python3 cf2dns.py              # 正式跑一轮
```

定时任务（按 TTL 600 取 30 分钟一轮）：

```cron
*/30 * * * * /path/to/cf2dns/cf2dns.py >/dev/null 2>&1
```

日志默认写到 `/var/log/cf2dns.log`（可用 `CF2DNS_LOG` 改路径），建议配 logrotate。

## 配置

`config.json` 全部字段：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `secret_id` / `secret_key` | 必填 | 腾讯云 API 密钥，用于 DNSPod |
| `domain` | 必填 | 主域名，如 `example.com` |
| `subdomain` | `@` | 要写记录的子域名，`@` 为根域名 |
| `default_ip` | 无 | 「默认」线路的固定 IP（通常是 Cloudflare 分配给你的 Anycast IP），不配则跳过该线路 |
| `fallback_ips` | 见示例 | 各线路候选全灭时的兜底 IP |
| `lines` | 见示例 | `线路名 -> {pool, records}`，`pool` 取 `CT`/`CU`/`CM`/`null` |
| `ttl` | `600` | 记录 TTL，DNSPod 免费版别改小 |
| `probe.path` | `/robots.txt` | 探测路径，选静态资产 |
| `probe.timeout` / `probe.attempts` | `3` / `2` | 单次握手超时、每轮尝试次数 |
| `switch.rotate_after` | `21600` | 允许轮换健康 IP 的最小间隔（秒） |
| `switch.rotate_gain_ms` | `25` | 轮换需要拿到的最小延迟收益 |
| `blacklist_ttl` / `blacklist_fail_threshold` | `21600` / `2` | 黑名单冷却时长、连续失败几轮才拉黑 |
| `alert_cooldown` | `21600` | 同类告警的冷却时间 |
| `telegram_env_file` | `/etc/cf2dns/telegram.env` | 内含 `TG_TOKEN` / `TG_CHAT`，不配则不发告警 |
| `www_cname` | 无 | 配了就维护 `www` 的 CNAME，如 `example.com.` |
| `hostmonit_key` | 公开 key | Hostmonit 优选池的 key，可换自己的 |

路径类环境变量：`CF2DNS_CONFIG`、`CF2DNS_LOG`、`CF2DNS_STATE_DIR`、`CF2DNS_LOCK`；也可以 `--config` 指定配置文件。

运行期文件（默认 `/var/lib/cf2dns/`）：`state.json`（各线路上次变更时间、失败计数）、`blacklist.json`、`cf-ips-v4.txt`（网段缓存）。

## 验证

按运营商模拟递归查询（ECS），看各线路实际返回什么：

```bash
dig +short @<你的权威NS> example.com A +subnet=202.96.128.86   # 电信
dig +short @<你的权威NS> example.com A +subnet=221.5.88.88     # 联通
dig +short @<你的权威NS> example.com A +subnet=211.136.192.6   # 移动
dig +short @<你的权威NS> example.com A +subnet=8.8.8.8         # 境外
```

检查记录里的每个 IP 是否真能出页面：

```bash
curl -o /dev/null -w '%{http_code}\n' --resolve example.com:443:<ip> https://example.com/robots.txt
```

## 安全

- **密钥不入库**：仓库里只有 `config.example.json`；`.gitignore` 已排除 `config.json`。
- **最小权限**：给脚本单独建一个腾讯云子账号，只授予 DNSPod 的记录读写权限，不要用主账号密钥。
- **文件权限**：`config.json` 与 Telegram env 文件都设成 `600`，属主是运行 cron 的用户。
- **改动范围可控**：脚本只操作 `domain` + `subdomain` 下、`lines` 里列出的线路的 A 记录，加上可选的 `www` CNAME；不碰 MX / TXT / 其他子域名。
- **不信任数据源**：候选 IP 必须落在 Cloudflare 官方网段内才会被写入；接口拉不到时用缓存，缓存也没有时用内置列表，绝不跳过校验直接写。

## 已知限制

- 优选池里的「某运营商低延迟」是在国内测出来的排序；脚本本身只验证「这个 IP 现在能不能出你的页面」，并按从运行机器看到的握手耗时排序。它证明不了「对某个运营商最快」。
- 从境外机器探测无法感知国内某条线路被墙，只能靠后续探测失败间接发现。
- DNSPod 免费版同一线路最多 2 条 A 记录，想再多得升级套餐。
- Cloudflare 的服务条款对「优选 IP」态度不明（社区里有因此停售退款的先例），使用风险自负。

## License

MIT
