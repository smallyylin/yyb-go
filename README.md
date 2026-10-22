# yyb-go

微信扫码登录 + wxapp 接口代理服务（Go）。提供扫码登录取 `login_buffer`、账号管理、以及
`getCode` / `getPhoneNumber` / `operateWxData` 三个上游调用的 HTTP 封装。

> **本服务持有可代表真实微信账号的凭据。** 启动时必须提供认证口令，否则进程拒绝启动。
> 部署时请只监听 `127.0.0.1`，由反向代理对外暴露。

---

## 快速开始

### 本地运行

```bash
export YYB_AUTH_TOKEN='换成你自己的强口令'
go run ./cmd/yyb-go -host 127.0.0.1 -port 8000
```

未设置 `YYB_AUTH_TOKEN` 时程序会生成一个临时口令并打印到日志（重启即失效），
这是刻意的 fail-closed 设计：宁可临时口令，也不开一个裸奔的账号库。

### Docker

```bash
# 必须设置，否则 compose 直接报错退出
export YYB_AUTH_TOKEN='换成你自己的强口令'

docker compose up -d --build
docker compose logs -f
```

容器只绑定 `127.0.0.1:8000`，公网访问请走宿主机 nginx 反代。

---

## 认证

除 `/health` 外，**所有**端点都需要认证。三种传法等价：

```bash
# 1) HTTP Basic
curl -u "admin:$YYB_AUTH_TOKEN" http://127.0.0.1:8000/accounts

# 2) 自定义头（口令含 # $ 等字符时最省事）
curl -H "X-Auth-Token: $YYB_AUTH_TOKEN" http://127.0.0.1:8000/accounts

# 3) Bearer
curl -H "Authorization: Bearer $YYB_AUTH_TOKEN" http://127.0.0.1:8000/accounts
```

口令比较使用常量时间实现，避免通过响应时间逐字节爆破。

---

## 端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 存活探测，**免认证** |
| GET | `/` | 控制台页面 |
| GET | `/scan` | 扫码添加账号页面 |
| POST | `/qr` | 创建扫码会话，返回 `session_id` 与二维码 |
| GET | `/qr/{sid}/image` | 二维码图片 |
| GET | `/qr/{sid}/poll` | 轮询扫码状态（服务端合并并发轮询） |
| POST | `/qr/{sid}/confirm` | 确认授权并入库（幂等，可重试） |
| GET | `/accounts` | 账号列表 |
| DELETE | `/accounts?ref=` | 删除账号 |
| GET | `/accounts/avatar?ref=` | 账号头像 |
| POST | `/accounts/refresh` | 刷新存活状态；不带 `ref` 处理全部 |
| POST | `/accounts/resync` | 重新同步资料；不带 `ref` 处理全部 |
| POST | `/wxapp/getCode` | 取小程序 code |
| POST | `/wxapp/getPhoneNumber` | 取手机号 |
| POST | `/wxapp/operateWxData` | 云函数代理 |

`ref` 可以是数据库 `id`、`uin` 或 `openid`。

交互式文档：`/docs/index.html`，OpenAPI JSON：`/openapi.json`。

---

## 配置

### 命令行参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-host` | `127.0.0.1` | 监听地址 |
| `-port` | `8000` | 监听端口 |
| `-resource-root` | `./resource` | 运行期资源目录 |
| `-db` | `yyb.db` | SQLite 文件名（位于 `<resource-root>/db`） |
| `-tcp-proxy` | 空 | `socks5://host:port` 或 `http-connect://host:port` |
| `-auth-user` | `admin` | Basic 用户名（亦可用 `YYB_AUTH_USER`） |
| `-auth-token` | 空 | 认证口令（亦可用 `YYB_AUTH_TOKEN`） |
| `-session-ttl` | `30m` | 上游会话缓存时长 |
| `-request-timeout` | `8s` | 单次上游请求超时 |

### 反向代理示例（nginx）

```nginx
location / {
    proxy_pass         http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    # 扫码轮询最长挂 35s，读超时要留足余量
    proxy_read_timeout 60s;
}
```

---

## 本次修复清单

对照原始代码逐条审计后修复的问题：

### 安全

1. **全站零鉴权**（最严重）— 任何人都能列出所有微信账号、调用 `getPhoneNumber`、
   删除账号。现为默认拒绝：无口令直接拒绝启动，中间件覆盖全部路由，仅 `/health` 豁免。
2. **二维码路径穿越** — `/qr/{sid}/image` 的 `sid` 直接拼进文件路径，`../` 可读写目录外
   文件。现在只接受服务端自己生成的 16 字节小写十六进制 ID。
3. **开放重定向 / SSRF** — `serveAvatar` 对数据库里的任意 http(s) 地址无条件 302；
   `downloadAvatar` 会请求任意 URL。现在两者都强制 https + 微信图片域名白名单，
   禁掉内嵌凭据、协议相对 URL 和内网地址，并禁止跟随重定向。
4. **任意文件读取** — `serveAvatar` 用数据库里的路径直接 `ServeFile`。现在先解析并确认
   路径落在 `resource/avatars` 之内，且必须是普通文件。
5. **LZ4 解压炸弹（可远程触发的 OOM）** — `lz4Decompress` 无输出上限，一个几十 KB 的
   畸形响应能声明数 GB 输出。现限制单次解压 8 MB。
6. **前端 XSS** — `scan.html` 把微信昵称直接插入 `innerHTML`。改为 DOM 节点 +
   `textContent`。
7. 头像下载禁用重定向跟随，避免借 302 打内网。

### 并发与稳定性

8. **扫码轮询互斥锁错用** — `PollQRCode` 持锁做 35 秒长轮询，前端每 1.5s 轮询一次，
   请求必然堆积并互相堵死。改为「锁只保护状态、网络调用在锁外」，并合并并发轮询：
   同一窗口内多个轮询共享一次上游请求。
9. **`Pool.run` 变量遮蔽** — 内层 `res, err :=` 遮蔽了外层 `err`，代理回退路径会返回
   `(nil, nil)`，上层当成空成功。
10. **连接泄漏** — `loginAndSession` 在候选循环内 `defer mc.close()`，失败重试时连接不会
    及时释放。改为每个候选独立函数持有连接生命周期。
11. **mmtls 记录读取死循环** — `parseRecords` 消费 0 字节时 `rxbuf` 不前进，循环空转并
    无限增长。现在检测到不可解析的完整头就报错，并给缓冲区加 1 MB 上限。
12. **握手循环无上限** — `recvServerFlight` 的 `for {}` 无迭代上限。加 16 条消息上限。
13. **HTTP 服务无超时** — 只设了 `ReadHeaderTimeout`，缺 `Read/Write/Idle` 与
    `MaxHeaderBytes`。现全部补齐，防 slowloris 与 goroutine 泄漏。
14. **sessions 表无限增长** — `PurgeExpiredSessions` 从未被调用。进程内加 10 分钟定时清理。
15. **无边界读取** — shortlink / HTTPDNS / 二维码图片的 `io.ReadAll` 全部加上限。
16. **批量接口串行且全崩** — `refresh` / `resync` 单个账号失败即返回 500 并中断其余账号。
    改为按账号独立报错，并给整批加超时上限。

### 正确性

17. **刷新后不清缓存会话** — `refreshLiveness` 更新了 `login_buffer` 却保留旧会话，
    后续调用一直复用失效 socket 直到自然过期。现在刷新/失效都会清掉缓存会话
    （含代理/直连两种键）。
18. **confirm 非幂等** — 成功后立刻销毁会话，浏览器丢响应或用户重复点击就拿到 404。
    现保留会话，登录凭据缓存在 session 上，重复 confirm 返回同一账号。
19. **`unknown` 被当作终态** — 上游返回无法归类时（多为代理抖动）立即销毁会话，
    一次可恢复的抖动变成硬 404。现在只把 `expired` / `cancelled` 当终态。
20. **二维码写盘与注册顺序颠倒** — 先注册后写盘，并发请求可能在窗口期把新文件当成
    垃圾清掉。改为先写盘再注册，快照在同一把锁内取。
21. **`sessionFromBlob` 类型脆弱** — `toBlob()` 输出里 `psk_entry` 是 struct，
    直接回灌会报 `missing psk_entry`，而同样的数据从 SQLite 读出来却正常。
    加一层 JSON 归一化，两条路径行为一致。
22. **`invokeWXApp` 两次读旧凭据** — 会话检查与实际调用之间存在竞态，且刷新后仍用
    旧 `login_buffer` 重试。改为失败后再刷新、重读账号、清会话后重试。
23. 删除死代码 `sortedKeys`（无调用者）、未使用的 `requestLogger` 保持原样保留接口。

### 测试

新增回归测试覆盖上述关键修复：

- `internal/httpapi`：鉴权强制（13 个受保护端点逐一断言 401）、Bearer/自定义头、
  无口令拒绝启动、二维码路径校验、头像 URL 白名单、OpenAPI 鉴权声明。
- `internal/protocol`：LZ4 炸弹拒绝、截断输入、正常往返、记录帧解析卡死场景、
  shortlink 长度校验、varint 溢出、session blob 往返与残缺拒绝。

```bash
go test ./...
go vet ./...
```

---

## 目录结构

```
cmd/yyb-go/          入口：参数解析、HTTP 服务、优雅关闭、会话清理定时器
internal/httpapi/    HTTP 层：路由、鉴权、账号 CRUD、wxapp 代理、OpenAPI
internal/protocol/   mmtls 握手、0-RTT shortlink、protobuf、HTTPDNS、连接池
internal/qr/         微信扫码 OAuth 流程
internal/store/      SQLite 持久化
resource/templates/  控制台与扫码页面
```
