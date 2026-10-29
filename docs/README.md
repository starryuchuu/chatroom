# 文档导航 / Documentation

[项目首页](../README.md) · [English README](../README_en.md) · [发布说明](../RELEASE_NOTES.md)

## 使用与安全 / Usage and security

| 文档 / Guide | 内容 / Contents |
| --- | --- |
| [单密码登录与迁移](SINGLE_PASSWORD.md) | OPAQUE、旧账号迁移、改密、云身份与离线备份 / OPAQUE, migration, password changes and recovery |
| [深浅色主题与截图](images/README.md) | Electron 深浅色、在线用户及旧版截图 / Electron themes, online users and historical screenshots |
| [群组功能](GROUP_FEATURES_GUIDE.md) | 创建、邀请、成员与群主操作 / Group management |
| [端到端加密与恢复](END_TO_END_ENCRYPTION.md) | 首次使用、指纹核对、密钥备份与保护范围 / Encryption, key recovery and limits |
| [加密存储](STORAGE_ENCRYPTION.md) | 数据格式、数据库迁移、备份与恢复 / Storage format, migration and recovery |
| [Go 服务端](../go-server/README.md) | 构建、启动和服务端配置 / Build, startup and configuration |

## 开发 / Development

| 文档 / Guide | 内容 / Contents |
| --- | --- |
| [开发与发布](../CONTRIBUTING.md) | 本地验证、跨平台检查和发布流程 / Tests, checks and releases |
| [客户端结构](CLIENT_ARCHITECTURE.md) | 模块职责、依赖、线程和事件流 / Client architecture and event flow |
| [Electron 桌面客户端](DESKTOP_CLIENT.md) | 新客户端运行、打包、界面入口及 Rust 替换边界 / New desktop development and packaging |
| [Desktop Protocol v2](DESKTOP_PROTOCOL.md) | Electron 与独立核心之间的版本化接口 / Versioned desktop/core contract |
| [Electron 迁移验证](reviews/ELECTRON_MIGRATION_VALIDATION.md) | 源码、成品、双窗口加密测试及验证范围 / Desktop migration validation |
| [发送恢复、缓存与搜索](SEND_RECOVERY_AND_CACHE.md) | v1.5.0 使用方式和边界 / Send recovery, bounded caches and local search |
| [发送恢复与缓存验证](reviews/SEND_RECOVERY_VALIDATION.md) | 本地回归、成品验证、合成测量与验证限制 / Local validation and measurement limits |
| [聊天区 UI 验证](reviews/CHAT_UI_VALIDATION.md) | 菜单、消息排版、搜索返回位置和界面回归 / Chat presentation and interaction checks |
| [草稿、待确认列表与时间验证](reviews/DRAFTS_SENDS_TIME_VALIDATION.md) | 会话隔离、逐条恢复、UTC 与旧历史兼容 / Drafts, send management and timestamps |
| [桌面、复制与渲染验证](reviews/DESKTOP_UI_VALIDATION.md) | 缩放、中文字体、复制、成品检查与渲染测量 / Desktop checks, copying and render measurements |
| [协议兼容性](../go-server/PROTOCOL_COMPATIBILITY.md) | Python / Go 线协议与兼容约定 / Protocol and compatibility |

文档中的启动、测试和构建命令默认从仓库根目录执行；标有 `cd go-server` 的命令在对应目录执行。

Run commands from the repository root unless a command explicitly changes directories.

## 历史记录 / Historical records

- [代码审查与修复记录](reviews/BUGFIX_REVIEW.md)
- [可靠性验证记录](reviews/RELIABILITY_VALIDATION.md)
- [重构与长会话性能记录](reviews/REFACTOR_VALIDATION.md)

这些记录说明特定版本执行过的检查；当前行为与保护范围请以使用文档和发布说明为准。

These reports document checks for specific releases. Refer to the current guides and release notes for current behavior and limits.

当前 Electron 截图位于 [images/](images/)，于 2026-10-27 至 2026-10-28 在真实窗口采集，展示浅色 / 深色聊天气泡、登录、在线用户、通知设置与消息发送状态。画面使用虚构演示数据，实际加密另有双服务端互操作验证。v1.3.2 的 Tk 截图保留作历史记录。新增指南和设计放在本目录，验证记录放在 `reviews/`。

Current Electron screenshots in [images/](images/) were captured in real windows on 2026-10-27 and 2026-10-28 with synthetic data. They show light/dark chat bubbles, login, online users, notification settings and message sending states. E2EE is tested separately against both servers; v1.3.2 Tk captures remain historical records.
