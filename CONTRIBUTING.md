# 开发与发布

## 模块职责

| 文件 / 目录 | 职责 |
| --- | --- |
| `client.py` | 客户端入口、服务器配置、供协议脚本使用的兼容导出 |
| `chatroom_client/models.py` | 账号状态及统一的私聊 / 群聊会话模型 |
| `chatroom_client/connection.py` / `protocol.py` | 无 Tk 依赖的认证、连接、线程与线协议 |
| `chatroom_client/app.py` / `events.py` | 应用操作、主线程事件泵和服务器事件处理 |
| `chatroom_client/history.py` | 会话分页游标、完成边界和重试 |
| `chatroom_client/view.py` / `group_view.py` | Tk 控件、输入、消息渲染及群窗口 |
| `chatroom_client/theme.py` | 统一桌面配色、跨平台字体及 Tk / ttk 控件样式 |
| `server.py` / `opaque_server.py` | Python 会话与业务操作、OPAQUE 认证和持久账号事务 |
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

会话统一使用 `ChatKey(kind, target)`，私聊用户名与群 ID 属于不同命名空间。消息、顺序、去重集合、未读编号和历史游标由 `Conversation` 一起管理。历史分页只在收到对应会话的 `history_end` 后推进游标，失败保留请求游标；登录快照或其他会话的完成事件不能清除当前分页请求。手动断开与新账号登录通过 `ClientState.reset_session()` 重置账号数据并保留进程内草稿；异常断线保留模型、视图和输入，重新认证后补取遗漏消息。视图创建函数不能初始化或清空业务数据。设置不得保存密码或正文；同步完成游标必须在未读状态保存成功后推进。

依赖方向、事件流和扩展方式见[客户端结构说明](docs/CLIENT_ARCHITECTURE.md)。修改功能时测试可使用无 Tk 的模型或注入模拟视图；控件行为继续由真实 Tk 测试覆盖，不再绕过构造函数手动拼装 `ChatClient`。

## 本地验证

单密码改动需要覆盖 `test_opaque_core.py`、`test_opaque_runtime.py`、`test_opaque_server.py`、`test_single_password_interop.py` 及新增的客户端迁移/改密/恢复测试：错误密码、未知账号假记录、KE3 验证、状态顺序、旧服务器拒绝、旧账号原子迁移、代次 CAS、Python / Go 数据库往返与重启、取消和超时。验证改密或本机落盘失败不会替换身份，云端 identity-only 备份不能覆盖联系人信任、群批准或重放数据；另一设备改密后原本机 v2 信任仍需保留。

端到端加密改动需要覆盖 `test_e2ee_crypto.py`、`test_key_vault.py`、`test_encryption_view.py`、`test_e2ee_python.py` 和 `test_e2ee_interop.py`，以及控制器的信任/降级/重放测试。真实互操作用例同时验证两种服务端及共享数据库迁移。请保持 `ChatClient` 的正常入口默认要求 `opaque_v1` 和 `e2ee_v1`；旧协议兼容测试明确注入 `encryption=False`，仅覆盖尚未迁移账号，界面不提供关闭加密或认证降级的开关。不要仅凭服务端的历史标志信任已撤销密钥或旧群成员。

普通开发与源码运行使用 Python 3.11+、Go 1.24.5+，安装固定 `wasmtime==50.0.1`；仓库及源码包提供预编译 WASM，Go 通过 `wazero` 内嵌执行。无需为正常测试安装 Rust。Linux 需要 Tk、Xvfb 和 xauth；Windows 在桌面会话中运行，无需 `xvfb-run`。

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

## 发布

1. 同步更新根目录和 `go-server/` 的 `VERSION`，版本格式为 `vX.Y.Z`。
2. 更新两处 `RELEASE_NOTES.md`，说明修复、兼容性和升级方式。
3. 新增 Python 模块或 WASM 资源时，更新 README 文件结构及 `.github/workflows/release.yml` 的源码附件、源码压缩包与校验文件清单。普通源码包必须包含预编译核心；Python 客户端和服务端打包需收集 wasmtime 动态运行库及 `chatroom_client/opaque_core.wasm`，Go 需内嵌匹配的 WASM。PyInstaller 会自动收集静态导入的模块；加密库动态加载的曲线模块通过 `--collect-submodules Crypto.PublicKey` 收集。构建和发布流水线必须执行成品的 `--check-encryption-runtime` 自检，验证曲线签名、密钥协商、本机密钥库及实际 OPAQUE 注册/认证核心，不能只检查模块可以导入。
4. 将验证通过的提交推送到 `master`。版本文件的变更自动触发 `Release Chatroom`。
5. 确认 Windows / Linux 测试、Python 双平台构建及 Go 六平台构建均通过，Release 包含带预编译 WASM 的源码、可执行文件和 `SHA256SUMS`。示例、日志、截图及构建产物仅用虚构演示数据和公开别名，检查构建路径和元数据，避免个人信息进入发布附件。

发布工作流在测试成功后构建，并由最终发布任务创建指向该提交的版本标签和 GitHub Release。
