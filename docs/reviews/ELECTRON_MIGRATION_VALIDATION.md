# Electron 客户端迁移验证

验证日期：2026-10-27。目标版本：v2.0.2。环境：Linux x64、Python 3.12.14、Node.js 24.19.0、Electron 45.0.0、React 19.3.1、TypeScript 7.0.2、Vite 8.3.5；图形检查使用 Xvfb。本页记录本地验证范围；正式 Windows / Linux 发布检查由该版本的 Actions 执行。

## 已验证

- TypeScript 检查、Vite 与 Electron 主进程 / preload 构建通过。
- Python 全套回归运行 621 项：620 通过，1 项旧 Tk 成品 DPI 探针退役跳过。新 Electron 窗口覆盖 100% / 150% / 200% 缩放；旧 Tk 夹具不进入新客户端。
- `test_desktop_rpc.py` 的 9 项检查通过，覆盖版本不符、陈旧账号令牌、错误聊天键、草稿切换、确认期间断开、申请 socket 绑定、64 位消息编号、无 Tk 导入，以及两个真实服务端上的双客户端加密私聊 / 群聊和历史恢复。
- Playwright 的 4 个场景在源码启动和实际 Linux 打包客户端均通过：真实核心启动与隔离、注册表单、服务器配置、主题保存、Unicode 输入、侧栏、搜索、2,000 条消息虚拟渲染及缩放。
- 两个真实 Electron 窗口完成 OPAQUE 注册登录、添加好友、E2EE 私聊和群聊、双方显式群接收人核验、群改名，以及关闭后重新打开群详情。空输入发送禁用，保存确认后清空原输入。
- 冻结核心的 `--check-encryption-runtime` 通过。PyInstaller 包排除 tkinter，核心包不导入旧视图。ZIP 内核心与最终构建的核心 SHA-256 一致。
- Go 静态检查及完整竞态测试通过。53 项发布计划、说明提取、版本同步、原子推送与隐私回归通过，Actions 语法检查通过。
- `npm audit --omit=dev` 未报告运行依赖公告。发布隐私检查覆盖发布基线后的提交、本次源码、PNG、冻结核心、Electron 解包目录与 ZIP。

Linux 分发包为 `desktop/release/chatroom-desktop-linux-x64.zip`。代码和许可文件一同打包：项目 GPL、OPAQUE 第三方许可、React / React DOM / Scheduler / Lucide / Virtuoso 许可。Electron 的上游 Chromium 许可仍随其运行时提供。

## 测量边界

后续补回左侧栏底部「在线用户」入口，使用现有 `onlineUsers` 推送。真实双窗口场景验证人数包含自己、搜索 / 无结果、自身标记，以及另一客户端退出后列表从 2 人实时降为 1 人；更新后的 Linux 成品同样通过该场景。断线状态明确显示为上次列表，避免把缓存误报为当前在线。

虚拟列表渲染检查使用 2,000 条虚构消息，确认可见 DOM 消息数小于 100，并从最新位置搜索跳转到远处结果。它不代表网络吞吐基准。截图中的账号和文字全部来自虚构夹具；实际加密另用真实服务端和双核心 / 双窗口测试验证。

Windows 构建、冻结核心自检及 Electron 成品测试已加入现有 CI，但本工作区未执行 Windows 系统检查。macOS 仅提供打包配置，尚未加入发布矩阵。真实中文输入法的预编辑、候选窗口、系统通知和原生文件选择器仍需目标桌面上的人工体验检查。

补充 Windows 成品隐私兼容验证：从校验通过的 Electron 45.0.0 Windows x64 官方 ZIP 核验原始 `.rdata`；在 Linux 上交叉打包、写入 ASAR 完整性资源后，77 个文件的检查通过。新回归覆盖段被修改、其他段及尾部附加私人路径、显式禁止值和畸形 PE 边界。交叉打包只验证资源与隐私行为，不代表本地执行过 Windows 应用。
