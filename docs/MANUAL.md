# Underflow 使用手册

本手册面向**最终用户与运维人员**，覆盖 Web 端、命令行（CLI）、部署、导入导出、备份与故障排查。密码学细节见 [CRYPTO.md](CRYPTO.md)，部署细节见 [DEPLOY.md](DEPLOY.md)，安全事项见 [SECURITY.md](SECURITY.md) 与 [THREAT_MODEL.md](THREAT_MODEL.md)。

---

## 1. 核心概念

| 概念 | 说明 |
|---|---|
| 主密码（Master Password） | 你唯一需要记住的密码。它**只存在于你的设备内存**，用于派生所有密钥，绝不上传。 |
| 保险库（Vault） | 条目的容器。每个保险库有一个随机 256 位密钥（Vault Key），用主密码派生的密钥包裹后存到服务端。 |
| 条目（Item） | 一条记录（登录、安全笔记、银行卡、身份），整体加密后上传，服务端只能看到密文。 |
| 解锁 / 锁定 | “解锁”= 本地派生并缓存 Vault Key；“锁定”= 清除内存中的密钥，需重新输入主密码。 |
| 会话令牌 | 服务端用于识别你已登录的随机令牌。它**不能**解密数据，解密始终需要主密码。 |
| 服务端胡椒（Server Pepper） | 服务端密钥，用于保护登录校验值。**不在数据库中**，必须单独备份。 |

> 重要：忘记主密码后**无法找回**任何数据。服务端与运维人员都无法帮你解密。请务必妥善保管主密码。

---

## 2. 部署与启动

### 2.1 本地单机（推荐个人使用）

```bash
make build                 # 构建前端 + WASM + 二进制（需要 Go 1.26+、Node 20+）
./bin/underflow serve --local
# 浏览器打开 http://127.0.0.1:8080，创建账户
```

- `--local` 绑定回环地址并在你创建账户后关闭注册。
- 首次运行会在数据库旁自动生成 `.pepper` 文件（权限 0600），用于保护校验值。
- 数据文件默认 `./underflow.db`。可用 `--dsn /path/to/underflow.db` 指定。

### 2.2 自建服务器（systemd）

见 [DEPLOY.md](DEPLOY.md#systemd)。关键点：设置 `UF_SERVER_PEPPER`、`UF_REGISTRATION=closed`，并用反向代理提供 HTTPS。

### 2.3 云端（Docker Compose）

见 [DEPLOY.md](DEPLOY.md#docker-compose-cloud)。组件为 PostgreSQL + Underflow + Caddy（自动 HTTPS）。

### 2.4 仅需 CLI、不想开服务端？

CLI 通过 HTTP 与 `underflow serve` 通信。最省事的组合是：本机后台跑 `serve --local`，CLI 指向 `http://127.0.0.1:8080`。

---

## 3. Web 端使用

打开服务地址后：

### 3.1 创建账户
1. 点击“No account? Create one”。
2. 输入邮箱与主密码（至少 12 位），再次确认。
3. 提交后即登录并自动创建一个名为 `Default` 的保险库。

### 3.2 解锁（每次打开页面）
零知识应用的特性：即使浏览器留有会话，刷新页面后仍需输入主密码来本地派生密钥。输入邮箱与主密码，点击 **Unlock**。

### 3.3 管理条目
- **New item**：新建条目，填写名称、用户名、密码、URL、备注。密码输入框旁有 **Generate**（生成随机密码）与 **Show**（显示明文）。
- **搜索**：左侧搜索框按名称、用户名、URL 过滤（在本地解密后匹配）。
- **查看/复制**：点击条目查看详情；点击字段旁的 **Copy** 复制。密码默认以 `••••••••` 显示，复制后剪贴板会在约 30 秒后被清空。
- **编辑/删除**：详情页的 **Edit** / **Delete**。

### 3.4 自动锁定
右上角 **Auto-lock** 可选择 1/5/10/30/60 分钟。无操作达到时长后会自动清除内存密钥并回到解锁界面（该偏好保存在浏览器本地，非敏感信息）。

### 3.5 退出
- **Lock**：仅清除本机内存密钥，保留登录会话。
- **Log out**：撤销服务端会话并清除本地密钥。

---

## 4. 命令行（CLI）

### 4.1 全局标志

| 标志 | 说明 |
|---|---|
| `--server <url>` | 服务端地址，覆盖配置文件 |
| `--email <email>` | 账户邮箱，覆盖配置文件 |
| `--config-dir <dir>` | 配置目录，默认 `~/.config/underflow`（也可用环境变量 `UNDERFLOW_CONFIG_DIR`） |

主密码一律通过交互式隐藏输入或标准输入读取，**不提供明文的 `--password` 参数**，避免进入 shell 历史。

### 4.2 命令总览

```
underflow serve        运行 Web/API 服务
underflow register     创建账户与保险库
underflow login        登录并缓存保险库密钥
underflow unlock       解锁（重新派生并缓存密钥）
underflow lock         忘记缓存的密钥
underflow logout       撤销会话并清除密钥
underflow whoami       查看当前账户与锁定状态
underflow item ...     条目管理（add/list/get/edit/rm）
underflow sync         拉取并解密服务端变更
underflow gen          生成随机密码
underflow export       导出解密后的条目
underflow import       从 CSV/JSON 导入
underflow password     修改主密码（重新包裹保险库密钥）
underflow version      打印版本
```

### 4.3 `serve` —— 运行服务端

```bash
underflow serve --listen 0.0.0.0:8080 --driver postgres \
  --dsn "postgres://user:pass@host:5432/underflow?sslmode=require" \
  --registration closed --tls-cert cert.pem --tls-key key.pem
```

标志：`--listen`、`--driver`(`sqlite|postgres`)、`--dsn`、`--registration`(`open|closed|invite`)、`--profile`(`interactive|moderate|paranoid`)、`--tls-cert`、`--tls-key`、`--local`、`--insecure`。

对应环境变量见 [DEPLOY.md](DEPLOY.md#configuration)（`UF_LISTEN_ADDR`、`UF_DB_DRIVER`、`UF_DB_DSN`、`UF_SERVER_PEPPER`、`UF_REGISTRATION`、`UF_INVITE_CODE`、`UF_ARGON2_PROFILE`、`UF_SESSION_TTL`、`UF_TRUSTED_PROXIES`、`UF_LOG_LEVEL`、`UF_TLS_CERT`、`UF_TLS_KEY`、`UF_INSECURE`）。命令行标志优先于环境变量。

### 4.4 账户与会话

```bash
# 创建账户（会提示输入两次主密码）
underflow register --server http://127.0.0.1:8080 --email you@example.com
underflow register --server https://pm.example.com --email you@example.com --invite CODE --profile moderate

# 登录并缓存保险库密钥（提示输入主密码）
underflow login

# 锁定 / 解锁
underflow lock
underflow unlock        # 提示输入主密码

# 查看状态
underflow whoami
# server:   http://127.0.0.1:8080
# email:    you@example.com
# user id:  <uuid>
# logged in: true
# vault:    unlocked

# 退出登录
underflow logout
```

说明：
- `register` 只需一次，之后用 `login`。若配置里已有 `--email`/`--server`，可省略。
- `lock` 只清除本地缓存密钥，保留会话；`unlock` 重新派生。`logout` 会撤销服务端会话。
- 若密码错误，登录会以非零退出码失败并打印 `invalid_credentials`。

### 4.5 条目管理 `item`

新增：

```bash
# 自动生成密码
underflow item add --name example.com --username alice --url https://example.com --generate --length 24

# 从标准输入读取密码（适合脚本；不会进入历史）
printf 'MySecret!42\n' | underflow item add --name github.com --username bob --password-stdin

# 交互式输入密码（提示隐藏）
underflow item add --name bank.example --username alice

# 仅记录、不要密码（例如安全笔记）
underflow item add --name "Wi-Fi 密码" --type note --no-password --notes "..."

# 指定保险库（默认唯一已解锁的保险库）
underflow item add --name x --vault <vault-id>
```

标志：`--name`(必填)、`--username`、`--url`、`--notes`、`--type`(`login|note|card|identity`)、`--vault`、`--generate`、`--length`(默认 20)、`--password-stdin`、`--no-password`。

列表 / 查看：

```bash
underflow item list
underflow item list --show-passwords
underflow item get example.com            # 密码以 **** 显示
underflow item get example.com --show     # 显示明文
underflow item get <uuid>                 # 也可用条目 id
```

编辑：

```bash
underflow item edit example.com --username alice2
underflow item edit example.com --generate           # 生成新密码并保留旧密码历史
printf 'NewPass!42\n' | underflow item edit example.com --password-stdin
```

标志：`--name`、`--username`、`--url`、`--notes`、`--generate`、`--length`、`--password-stdin`（仅对显式给出的字段生效；至少需改动一项）。

删除：

```bash
underflow item rm example.com
```

> `get` / `edit` / `rm` 的 `<id|name>`：先按条目 id 精确匹配，再按名称不区分大小写匹配；同名多条会报错，请改用 id。

### 4.6 同步

```bash
underflow sync
# Synced 3 item(s) (1 deleted), revision=42
```

`sync` 从服务端拉取当前全部条目并统计（删除项计入 deleted）。`item list/get` 等命令在读取时会自行解密最新数据。

### 4.7 密码生成器

```bash
underflow gen                          # 20 位，含大小写/数字/符号
underflow gen --length 32 --count 5
underflow gen --no-symbols             # 排除符号
underflow gen --allow-ambiguous        # 允许易混淆字符（l/I/1/O/0 等）
```

标志：`--length`(默认 20)、`--count`(默认 1)、`--no-lower`、`--no-upper`、`--no-digits`、`--no-symbols`、`--allow-ambiguous`。默认排除易混淆字符，且保证每类至少一个字符。

### 4.8 导出 / 导入

```bash
# 导出（解密后输出，注意保护输出文件）
underflow export --format json --output backup.json
underflow export --format csv  > backup.csv

# 导入（按扩展名推断格式，也可显式指定）
underflow import backup.csv
underflow import backup.json --format json --vault <vault-id>
```

- **JSON 导出**为条目对象数组，字段见 §5。
- **CSV 导出**列：`name,username,password,url,notes,type`。
- **CSV 导入**识别表头列 `name`、`username`、`password`、`url`、`notes`、`type`（缺省为 `login`）；无 `name` 的行会被跳过。
- 导出文件是**明文**，请存放在安全位置或加密后再保存。

### 4.9 修改主密码

```bash
underflow password
# 依次提示：当前主密码、新主密码、确认新主密码
```

修改后会自动用新密钥重新包裹保险库密钥，并撤销其它设备的会话（当前会话保留）。之后请用新主密码 `unlock`。

---

## 5. 条目数据结构（明文，加密前）

```json
{
  "id": "uuid",
  "type": "login",
  "name": "example.com",
  "username": "alice",
  "password": "…",
  "urls": ["https://example.com"],
  "totp": "otpauth://…",
  "notes": "备注",
  "tags": ["work"],
  "folder": "工作",
  "fields": [{ "name": "PIN", "value": "1234", "type": "hidden" }],
  "passwordHistory": [{ "password": "旧密码", "changedAt": "2026-01-01T00:00:00Z" }],
  "favorite": false,
  "createdAt": "2026-01-01T00:00:00Z",
  "updatedAt": "2026-01-01T00:00:00Z"
}
```

以上 JSON 会被客户端加密后上传；服务端仅保存密文与最小元数据（id、vaultId、revision、updatedAt、deleted）。

---

## 6. 文件与配置位置

| 路径 | 内容 | 权限 |
|---|---|---|
| `~/.config/underflow/config.toml` | 非敏感配置：`server`、`email`、`device_id` | 0600 |
| `~/.config/underflow/secrets.json` | 会话令牌、KDF 参数、缓存的保险库密钥 | 0600 |
| `<dsn>.pepper`（本地 SQLite） | 服务端胡椒（由服务端生成） | 0600 |
| `underflow.db`（SQLite） | 服务端数据库（仅密文） | 视部署而定 |

- 覆盖配置目录：`--config-dir` 或 `UNDERFLOW_CONFIG_DIR`。
- `lock` 会从 `secrets.json` 移除缓存的保险库密钥；`logout` 会移除令牌与密钥。

---

## 7. 备份、迁移与恢复

需要备份两样，且**分开保存**：

1. **数据库**：SQLite 直接拷贝 `underflow.db`（先停服务）；PostgreSQL 用 `pg_dump`。
2. **服务端胡椒**：`UF_SERVER_PEPPER` 或本地 `.pepper` 文件。

丢失胡椒会导致所有账户无法通过登录校验；丢失数据库可用备份恢复。**两者都无法恢复遗忘的主密码。**

迁移到新服务器：
```bash
# 新机：设置相同的 UF_SERVER_PEPPER，导入数据库，启动服务
# 客户端：仍用原主密码登录即可，无需重新注册
```

---

## 8. 安全建议

- 主密码至少 16 位且唯一；使用密码管理器记忆。
- 云端部署始终启用 HTTPS（内置 TLS 或 Caddy）。Underflow 在终止 TLS 时自动发送 HSTS。
- 账户创建完成后设 `UF_REGISTRATION=closed`（或使用 `UF_REGISTRATION=invite` + `UF_INVITE_CODE`）。
- 妥善保管 `UF_SERVER_PEPPER`，不要与数据库放在同一备份介质。
- 主机层面关闭 swap 与 core dump，限制数据库与备份访问权限。
- 记住：Web 端的安全性取决于服务端下发的 JS；对高价值账户可优先使用 CLI（同一加密核心的原生实现）。

更多见 [SECURITY.md](SECURITY.md) 与 [THREAT_MODEL.md](THREAT_MODEL.md)。

---

## 9. 故障排查（FAQ）

**Q：登录提示 `invalid_credentials`？**
主密码错误，或邮箱不正确。注意 `unlock`/`login` 会对邮箱与主密码分别校验。

**Q：`item` 命令报 “vault is locked”？**
先执行 `underflow unlock`（会提示输入主密码），或 `underflow login`。

**Q：命令报 “not logged in”？**
执行 `underflow login`，或确认 `--server`/`--email` 与配置文件正确。

**Q：浏览器刷新后又要输入主密码？**
这是预期行为（零知识，密钥仅存内存）。可调大 Auto-lock 时长，但仍无法跨刷新保留密钥。

**Q：`429 rate_limited`？**
登录/注册触发限流（默认每 IP+账户 5 分钟内 10 次）。稍后重试。

**Q：`409 revision_conflict`？**
条目在别处被修改。运行 `underflow sync` 后重试；Web 端会以最新数据为准重新编辑。

**Q：如何彻底停用服务端？**
停进程即可，数据在数据库文件中。`underflow serve` 启动时自动执行迁移，升级前请先备份。

**Q：能多人共用一个部署吗？**
可以。Underflow 是多用户架构，各用户数据严格隔离；但当前版本**不支持跨用户共享保险库**（属后续规划）。

**Q：忘记主密码怎么办？**
无法恢复。这也意味着任何声称能“帮你找回”的做法都是不可信的。

---

## 10. HTTP API 参考

面向集成开发者：完整接口定义见 [`api/openapi.yaml`](../api/openapi.yaml)。所有字段均为密文或公开参数，接口路径前缀 `/api/v1`。CLI 与 Web 端使用同一套 API。
