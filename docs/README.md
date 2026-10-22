# 文档导航 / Documentation

[项目首页](../README.md) · [English README](../README_en.md) · [发布说明](../RELEASE_NOTES.md)

## 使用与安全 / Usage and security

| 文档 / Guide | 内容 / Contents |
| --- | --- |
| [单密码登录与迁移](SINGLE_PASSWORD.md) | OPAQUE、旧账号迁移、改密、云身份与离线备份 / OPAQUE, migration, password changes and recovery |
| [群组功能](GROUP_FEATURES_GUIDE.md) | 创建、邀请、成员与群主操作 / Group management |
| [端到端加密与恢复](END_TO_END_ENCRYPTION.md) | 首次使用、指纹核对、密钥备份与保护范围 / Encryption, key recovery and limits |
| [加密存储](STORAGE_ENCRYPTION.md) | 数据格式、数据库迁移、备份与恢复 / Storage format, migration and recovery |
| [Go 服务端](../go-server/README.md) | 构建、启动和服务端配置 / Build, startup and configuration |

## 开发 / Development

| 文档 / Guide | 内容 / Contents |
| --- | --- |
| [开发与发布](../CONTRIBUTING.md) | 本地验证、跨平台检查和发布流程 / Tests, checks and releases |
| [客户端结构](CLIENT_ARCHITECTURE.md) | 模块职责、依赖、线程和事件流 / Client architecture and event flow |
| [协议兼容性](../go-server/PROTOCOL_COMPATIBILITY.md) | Python / Go 线协议与兼容约定 / Protocol and compatibility |

文档中的启动、测试和构建命令默认从仓库根目录执行；标有 `cd go-server` 的命令在对应目录执行。

Run commands from the repository root unless a command explicitly changes directories.

## 历史记录 / Historical records

- [代码审查与修复记录](reviews/BUGFIX_REVIEW.md)
- [可靠性验证记录](reviews/RELIABILITY_VALIDATION.md)

这些记录说明特定版本执行过的检查；当前行为与保护范围请以使用文档和发布说明为准。

These reports document checks for specific releases. Refer to the current guides and release notes for current behavior and limits.

界面截图位于 [images/](images/)，于 2026-10-22 从已发布 v1.3.0 实拍，展示单密码登录及迁移、旧密钥解锁入口。新增指南、设计说明和截图统一放在本目录，历史验证材料放在 `reviews/`。

Screenshots in [images/](images/) were captured from the released v1.3.0 on 2026-10-22 and show single-password login, legacy migration and legacy-key unlock entries. Keep guides, design notes and screenshots here, and historical validation reports in `reviews/`.
