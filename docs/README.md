# 文档导航 / Documentation

[项目首页](../README.md) · [English README](../README_en.md) · [发布说明](../RELEASE_NOTES.md)

## 使用与安全 / Usage and security

| 文档 / Guide | 内容 / Contents |
| --- | --- |
| [单密码登录与迁移](SINGLE_PASSWORD.md) | OPAQUE、旧账号迁移、改密、云身份与离线备份 / OPAQUE, migration, password changes and recovery |
| [深浅色主题与截图](images/README.md) | 即时切换、主题保存及 v1.3.2 实拍 / Theme switching, persistence and v1.3.2 captures |
| [群组功能](GROUP_FEATURES_GUIDE.md) | 创建、邀请、成员与群主操作 / Group management |
| [端到端加密与恢复](END_TO_END_ENCRYPTION.md) | 首次使用、指纹核对、密钥备份与保护范围 / Encryption, key recovery and limits |
| [加密存储](STORAGE_ENCRYPTION.md) | 数据格式、数据库迁移、备份与恢复 / Storage format, migration and recovery |
| [Go 服务端](../go-server/README.md) | 构建、启动和服务端配置 / Build, startup and configuration |

## 开发 / Development

| 文档 / Guide | 内容 / Contents |
| --- | --- |
| [开发与发布](../CONTRIBUTING.md) | 本地验证、跨平台检查和发布流程 / Tests, checks and releases |
| [客户端结构](CLIENT_ARCHITECTURE.md) | 模块职责、依赖、线程和事件流 / Client architecture and event flow |
| [发送恢复、缓存与搜索](SEND_RECOVERY_AND_CACHE.md) | v1.4.0 之后的开发改动、使用方式和边界 / Unreleased send recovery, bounded caches and local search |
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

界面截图位于 [images/](images/)，于 2026-10-23 从 v1.3.2 源码实拍，包含浅色登录、主界面及深浅两种聊天主题。登录页与聊天页右上角可点击“深色模式” / “浅色模式”即时切换，并记住选择。新增指南、设计说明和截图统一放在本目录，历史验证材料放在 `reviews/`。

Screenshots in [images/](images/) were captured from v1.3.2 source on 2026-10-23 and show light login/main views plus light and dark chats. Use “深色模式” / “浅色模式” at the top right of login or chat to switch immediately and save the choice. Keep guides, design notes and screenshots here, and historical validation reports in `reviews/`.
