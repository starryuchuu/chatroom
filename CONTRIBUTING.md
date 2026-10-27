# 开发与发布

## Electron 桌面开发

当前桌面入口为 Electron + React + TypeScript，运行与打包见 [桌面指南](docs/DESKTOP_CLIENT.md)，Rust 可替换边界见 [Desktop Protocol v1](docs/DESKTOP_PROTOCOL.md)。从 `desktop/` 运行 `npm ci`、`npm run build`、`npm test`（Linux 无显示环境加 `xvfb-run -a`）。`tests/test_desktop_rpc.py` 使用无界面核心验证两个真实服务端。旧 Tk 视图及测试暂留作历史回归，不进入新客户端成品。

## 模块职责

| 文件 / 目录 | 职责 |
| --- | --- |
| `client.py` | 客户端入口、服务器配置、供协议脚本使用的兼容导出 |
| `chatroom_client/models.py` | 账号状态及统一的私聊 / 群聊会话模型 |
| `chatroom_client/connection.py` / `protocol.py` | 无 Tk 依赖的认证、连接、线程与线协议 |
| `chatroom_client/app.py` / `events.py` | 应用操作、主线程事件泵和服务器事件处理 |
| `chatroom_client/history.py` | 会话分页游标、完成边界和重试 |
| `chatroom_client/sending.py` / 根 `send_receipts.py` | 待确认发送、结果查询及事务内幂等保存 |
| `chatroom_client/send_recovery_view.py` | 原页面逐条核对、重试与移除待确认记录 |
| `chatroom_client/search.py` | 当前已加载消息的搜索、导航与高亮 |
| `chatroom_client/request_context.py` | 连接、账号、群成员代次和请求令牌的共享校验 |
| `chatroom_client/login_view.py` / `message_list.py` | 登录卡片布局、有限窗口消息列表和控件复用 |
| `chatroom_client/message_actions.py` / `desktop_check.py` | 按需只读选择与复制、原生桌面和成品检查 |
| `chatroom_client/message_rows.py` | 消息排版、日期分隔、作者分组和原位消息信息 |
| `chatroom_client/view.py` / `group_view.py` | Tk 控件、输入、消息渲染及群窗口 |
| `chatroom_client/theme.py` | 统一桌面配色、跨平台字体及 Tk / ttk 控件样式 |
| `server.py` / `opaque_server.py` | Python 会话与业务操作、OPAQUE 认证和持久账号事务 |
| `server_handlers/` | 显式注入依赖的好友、群管理和消息处理器；入口负责认证、连接与资源清理 |
| `opaque-core/` / `opaque_runtime.py` | 固定 opaque-ke 的共享 WASM、Python 沙箱包装 |
| `chatroom_client/key_vault.py` | 单密码 v2 身份包装、本机信任、v1 迁移与完整离线备份 |
| `scripts/build_opaque.py` | 从锁定 Rust 源码重建并同步 Python / Go 的 WASM |
| `transport.py` | Python 协议 v2 报文认证、方向密钥与序号 |
| `storage.py` | Python 加密存储及旧库迁移 |
| `history_store.py` / `pending_store.py` | 历史分页查询 / 待处理申请持久化 |
| `chatroom_client/preferences.py` / `settings_view.py` | 账号隔离的元数据、服务器配置与设置界面 |
| `chatroom_client/activity.py` / `notifications.py` | 未读与已读位置、提醒策略和原生通知工作线程 |
| `chatroom_client/reconnect.py` / `sync.py` | 重连退避、取消令牌、断线消息补取和完成游标 |
| `go-server/internal/` | Go 服务端的协议、存储、业务处理和连接管理 |
| `tests/` | Python、真实 Tk 窗口及 Python / Go 互操作回归 |
| `docs/` | 使用指南、设计说明与截图；历史审查和验证记录放在 `docs/reviews/` |

新增技术文档和截图统一放在 `docs/`，并更新[文档导航](docs/README.md)。根目录的 README、贡献指南和发布说明保留为入口。

客户端后台线程由 `ConnectionManager` 创建和跟踪，线程目标不能捕获应用控制器或 Tk 对象。线程通过 `AuthResult` / `ServerEvent` 交付数据，由应用事件泵在主线程处理。关闭时中断网络和发送队列，等待线程退出、清理未消费认证结果后再销毁 Tk。视图在销毁聊天控件前取消排队的滚动回调。

会话统一使用 `ChatKey(kind, target)`，私聊用户名与群 ID 属于不同命名空间。消息、顺序、去重集合、未读编号和历史游标由 `Conversation` 一起管理。历史分页只在收到对应会话的 `history_end` 后推进游标，失败保留请求游标；登录快照或其他会话的完成事件不能清除当前分页请求。手动断开与新账号登录通过 `ClientState.reset_session()` 重置账号数据并保留按端点、账号与会话隔离的进程内草稿；异常断线保留模型、视图和输入，重新认证后补取遗漏消息。视图创建函数不能初始化或清空业务数据。设置不得保存密码或正文；同步完成游标必须在未读状态保存成功后推进。

依赖方向、事件流和扩展方式见[客户端结构说明](docs/CLIENT_ARCHITECTURE.md)。修改功能时测试可使用无 Tk 的模型或注入模拟视图；控件行为继续由真实 Tk 测试覆盖，不再绕过构造函数手动拼装 `ChatClient`。

## 本地验证

单密码改动需要覆盖 `test_opaque_core.py`、`test_opaque_runtime.py`、`test_opaque_server.py`、`test_single_password_interop.py` 及新增的客户端迁移/改密/恢复测试：错误密码、未知账号假记录、KE3 验证、状态顺序、旧服务器拒绝、旧账号原子迁移、代次 CAS、Python / Go 数据库往返与重启、取消和超时。验证改密或本机落盘失败不会替换身份，云端 identity-only 备份不能覆盖联系人信任、群批准或重放数据；另一设备改密后原本机 v2 信任仍需保留。

端到端加密改动需要覆盖 `test_e2ee_crypto.py`、`test_key_vault.py`、`test_encryption_view.py`、`test_e2ee_python.py` 和 `test_e2ee_interop.py`，以及控制器的信任/降级/重放测试。真实互操作用例同时验证两种服务端及共享数据库迁移。请保持 `ChatClient` 的正常入口默认要求 `opaque_v1` 和 `e2ee_v1`；旧协议兼容测试明确注入 `encryption=False`，仅覆盖尚未迁移账号，界面不提供关闭加密或认证降级的开关。不要仅凭服务端的历史标志信任已撤销密钥或旧群成员。

普通开发与源码运行使用 Python 3.11+，Go 推荐使用与 CI / 发布构建一致的 1.27.3；`go.mod` 的语言最低版本为 1.26.0，工具链固定 `go1.27.3`。`requirements.txt` 固定全部 Python 运行依赖及传递依赖，包括 `wasmtime==50.0.1`；构建可执行文件时安装 `requirements-build.txt`，它包含运行依赖及固定的 PyInstaller 和平台构建依赖。仓库及源码包提供预编译 WASM，Go 通过 `wazero` 内嵌执行，正常运行与测试无需 Rust。Linux 需要 Tk、Xvfb 和 xauth；Windows 在桌面会话中运行，无需 `xvfb-run`。

```bash
python -m pip install -r requirements.txt
cd go-server
go vet ./...
go test -race -count=1 ./...
go build -o ../go-interop-server ./cmd/server
cd ..
CHATROOM_GO_SERVER_EXE="$PWD/go-interop-server" xvfb-run -a python -m unittest discover -s tests -v
git diff --check
```

Windows 可使用 `go test -count=1 ./...`，构建 `go-interop-server.exe`，设置 `CHATROOM_GO_SERVER_EXE` 后直接执行 Python 测试。未设置此变量会跳过 Go 互操作及 Go 可靠性测试。测试使用临时数据库；Go 测试需要本机端口 `12346` 空闲，不能并行运行多个占用该端口的测试进程。

需要修改 OPAQUE 核心时，安装 Rust 1.87+ 和 `wasm32-unknown-unknown` 目标，执行：

```bash
rustup target add wasm32-unknown-unknown
python scripts/build_opaque.py
```

构建使用 `opaque-core/Cargo.lock`，同步生成 `chatroom_client/opaque_core.wasm` 与 `go-server/internal/opaqueauth/opaque_core.wasm`；提交前核对两份 SHA-256 一致。核心锁定 `opaque-ke=4.0.1`，采用 RFC 9807；上游对早期版本的审计不等于该版本、WASM 包装或本项目集成已独立审计。不要自行替换为普通密码哈希作为 OPAQUE 导出密钥，或把完整本机信任库同步到云端。具体协议和恢复约定见[单密码指南](docs/SINGLE_PASSWORD.md)与[协议兼容性](go-server/PROTOCOL_COMPATIBILITY.md)。

`tests/test_system_reliability.py` 会启动真实服务端，验证并发收发、进程强制终止、数据库写入故障、离线请求恢复、重连、TCP 分片和非法报文。默认每端使用 4 个客户端发送 168 条消息，适合每次 CI 运行。较大规模验证可单独执行：

```bash
CHATROOM_GO_SERVER_EXE="$PWD/go-interop-server" \
CHATROOM_STRESS_USERS=8 CHATROOM_STRESS_GROUP=100 CHATROOM_STRESS_PRIVATE=50 \
python -m unittest discover -s tests -p test_system_reliability.py -v
```

压力参数只影响并发收发场景：客户端数范围为 3–32，群消息数为每人 1–300，私聊消息数为每人 1–100。更高并发可设置 `32 / 25 / 10`，每端共 1,120 条消息。此测试文件不创建 Tk 窗口，无需 Xvfb。测试结果和边界见[可靠性验证记录](docs/reviews/RELIABILITY_VALIDATION.md)。

客户端测试通过 `ChatClient(root, preferences=PreferencesStore(persistent=False))` 注入内存设置，或使用独立临时配置文件，不应读写开发者的个人设置。`test_client_features_integration.py` 使用真实 Tk 客户端与两种服务端，覆盖 205 条离线消息的跨页补取、未读/免打扰、会话和草稿保留、取消重连及不自动重发。

`test_client_scrolling.py` 使用真实 Tk 验证长好友/群列表的选择、滚动与键盘导航位置，批量新消息和重连重绘的消息锚点，新消息入口以及细幅/标准/X11 滚轮事件。`test_client_layout.py` 和 `test_client_theme.py` 覆盖最小窗口、高 DPI、深浅色与输入保持；几何断言须处理原生映射事件并有界等待有效尺寸，不能只等待空闲任务或依赖固定睡眠。

登录与迁移并发修改须覆盖账号预留的成功、重复占用、失败、断开清理及旧认证与 OPAQUE 交错；群容量改动覆盖 256/257 边界、重复成员、满员邀请重试、已有超限群缩减和无效大列表不阻塞其他操作。密钥操作须验证核验所见指纹的 CAS，以及导出到本机库本身、符号链接和硬链接别名时拒绝覆盖。

## 依赖更新与漏洞检查

更新 Python 依赖时同时维护运行与构建锁中的直接、传递和平台条件依赖，在 Windows / Linux 验证安装与成品自检。Go 依赖由 `go.mod` / `go.sum` 固定；更新后运行静态、竞争、互操作和漏洞检查，保留预编译 WASM 与锁定 Rust 源的一致性。

Windows / Linux CI 执行以下 Python 检查，Linux CI 另执行 Go 检查；本地可分别在仓库根目录和 `go-server/` 运行：

```bash
python -m pip install pip-audit==2.10.1
python -m pip_audit --disable-pip --no-deps -r requirements-build.txt
cd go-server
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./cmd/server
```

`pip-audit` 检查列出的运行与构建包公告，`govulncheck` 分析指定服务端入口的可达漏洞；结果受公告库、平台和分析范围限制，不能据此声称所有依赖、构建产物或本项目均无漏洞。`.github/dependabot.yml` 已配置 Python、Go、Cargo 和 GitHub Actions 的定期更新；安全告警与自动安全更新需仓库管理员在 GitHub 设置中另行启用，不能把更新配置视为这些开关已经开启。

## 日常推送与发布

日常只需提交并 `git push`。`Daily CI` 根据文件变化选择检查：

| 改动 | 日常检查 |
| --- | --- |
| 文档 / 截图 | 版本一致性与源码隐私 |
| Electron 界面 | 类型与构建检查、运行依赖公告、真实 Linux Electron 测试 |
| Python 核心 / 服务端 | Linux Python 回归和真实 Python / Go 互操作；核心接口变化也检查桌面 |
| Go 服务端 | 上述互操作，加 Go 静态、竞争和公告检查 |
| OPAQUE / 发布脚本 / 工作流 | 所有关联检查；OPAQUE 从锁定源重建并比较两个内嵌 WASM |

日常不生成跨平台发布包。已有面向 `main` / `master` / `test` 的 PR 时，匹配相同提交的分支推送交给 PR 流程；GitHub API 不可用时仍执行检查。发布标签和主分支一起推送时，完整验证交给 Release 流程。需要分支保护检查时使用汇总项 **CI result**。

准备正式发版时，在 `RELEASE_NOTES.md` 添加 `# vX.Y.Z — 标题` 及该版本说明，将功能与文档提交 / 合并到 `master`，保持工作区干净，再从仓库根目录执行：

```bash
# 仅预览：不改文件、提交、标签或远端
python scripts/release.py 1.6.0 --dry-run

# 正式执行：同步版本、提交、创建标签、原子推送主分支和标签
python scripts/release.py 1.6.0
```

版本以根目录 `VERSION` 为准。命令自动同步 `go-server/VERSION`、`desktop/package.json` 和 `desktop/package-lock.json`（含 npm 根包版本），使用项目公开别名创建发布提交与注解标签，再执行完整源码 / 元数据隐私检查。只接受递增的 `vX.Y.Z`，拒绝脏工作区、非 master、重复标签和分叉的远端历史；推送不使用强制覆盖。若本地准备或推送中途失败，已有本地结果保留供检查；远端不接受原子推送时，不会只更新主分支。

`Release Chatroom` 只由版本标签触发，普通版本文件修改不会直接发布。它先验证标签对应的确切提交属于 `origin/master`、所有版本副本一致，并且仍是 master 当前发布版本，然后执行 Windows / Linux 完整回归，再构建双平台桌面 / Python 服务端与六平台 Go 服务端。构建、自检和发布均固定在该标签提交，手动重试也不会误用 master 后续代码。

发布失败可在 Actions 重跑原任务，或手动运行 `Release Chatroom` 并填写已有标签。不要为重试重复执行版本命令。流水线从 `RELEASE_NOTES.md` 提取对应版本的标题与正文作为 GitHub Release 文案，缺失或重复的版本说明会停止发布，无需另写第二份说明。

附件保留平台客户端 / 服务端、**一个完整源码 ZIP**、必要许可文件和 `SHA256SUMS`。源码 ZIP 包含客户端与两个服务端；不再重复上传客户端源码 ZIP 和零散 Python 文件。`scripts/release_assets.py` 统一验证清单并计算校验值。

成品仍须包含 wasmtime 动态运行库、OPAQUE WASM 和相关许可，并执行冻结核心的 `--check-encryption-runtime` 及实际 Electron 检查。发布隐私检查覆盖发布基线后的提交 / 注解标签、源码、PNG、嵌套 ZIP / PYZ 和最终附件。检查失败会停止发布，输出不回显私人姓名、邮箱或凭据。可选 `PRIVACY_FORBIDDEN_VALUES_JSON` 仍从仓库同名 Secret 读取；可用 `python scripts/check_release_privacy.py --require-alias-head --assets <附件目录>` 本地核验。

### 桌面成品验证

新客户端从 `desktop/` 执行 `npm test`，Linux 无显示环境使用 `xvfb-run -a npm test`。设置 `CHATROOM_DESKTOP_EXECUTABLE` 为解包客户端的绝对路径可检查实际打包产物。Playwright 覆盖真实 Electron 启动、设置、Unicode 输入、100% / 150% / 200% 缩放、深浅主题、搜索和 2,000 条虚构消息的虚拟渲染。

新核心使用 `core_client.py --check-encryption-runtime`，PyInstaller 成品支持相同参数。桌面程序不再使用 Tk 自检参数；旧 `desktop_check.py` 和 Tk 渲染脚本只作为历史验证材料。实际中文输入法候选窗口与预编辑仍需在 Windows / Linux 人工检查。

发布版本由上方的一键命令同步。本次流程改动没有更新版本号或发布。Windows / Linux 客户端附件改为 `chatroom-desktop-<platform>-<arch>.zip`，内置 `chatroom-core`；不要再构建旧 Tk 入口为客户端。完整源码包包含 `desktop/`、核心入口、两个服务端与预编译 OPAQUE WASM。
