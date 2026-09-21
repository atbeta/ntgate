# cntlm-next

Windows 上给 `git` / `npm` / `curl` 用的本地 HTTP 代理：把公司 `proxy.xxx.com:8080`（NTLM / Negotiate / PAC）收成无认证的 `127.0.0.1:3128`。

行为对齐 [Winfoom](https://github.com/ecovaci/winfoom)（当前用户 SSO、PAC、系统代理），交付是**单个 exe + TOML**，不需要 JDK。cntlm 那种进程自己掉线的问题，用 Rust 连接隔离 + 失败自动重拉（登录任务）来压。

## 要求

- Windows，域账号登录之后使用
- 不写密码；鉴权走当前登录会话（SSPI Negotiate，必要时 NTLM）

## 安装

从 [Releases](https://github.com/atbeta/cntlm-next/releases) 或 Actions 产物下载 `cntlm-next.exe`（Windows x64），放到任意目录，然后：

```bat
cntlm-next doctor
cntlm-next install
```

`install` 会在 Task Scheduler 里注册**当前用户登录触发**的任务（不是 LOCAL SYSTEM，否则 SSO 会 407），失败 5 秒后重试。

默认配置写在 `%LOCALAPPDATA%\cntlm-next\cntlm-next\config.toml`。

## 配置

```toml
listen = "127.0.0.1:3128"

# system = 跟随当前用户的 WinHTTP / IE 设置（PAC / WPAD / 静态代理）
# pac    = 使用 `pac` 指定的脚本
# proxy  = 固定 `upstream`
mode = "system"

# upstream = "proxy.xxx.com:8080"
# pac = "http://pac.xxx.com/proxy.pac"

auth = "auto"
test_url = "https://example.com"
```

## 命令

| 命令 | 作用 |
|------|------|
| `cntlm-next` / `run` | 前台跑本地代理 |
| `doctor` | 用当前用户打通上游，人话报错 |
| `print-env` | 打印 `HTTP_PROXY` 和 git 配置片段 |
| `install` / `uninstall` | 登录任务 |
| `status` | 配置路径与任务是否存在 |
| `-c path.toml` | 指定配置 |

```bat
cntlm-next print-env
```

把输出里的 `HTTP_PROXY` 配给 git / npm 即可。

## 开发（本仓库）

```bash
cargo test
cargo build --release
```

GitHub Actions 在 `windows-latest` 上交叉打 `x86_64-pc-windows-msvc` 的 `cntlm-next.exe`，推 `main` 可下 artifact；打 `v*` tag 会挂到 Release。

真实 SSO / PAC / 服务只能在 Windows 上验证。macOS 上 `cargo test` 覆盖配置、PAC 字符串、noproxy、HTTP 解析。

## 许可

MIT OR Apache-2.0
