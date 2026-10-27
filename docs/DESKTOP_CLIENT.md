# Electron 桌面客户端

v2.0.0 使用 Electron + React + TypeScript + Vite，替换旧 Tkinter 桌面界面。视觉参考 Codex Desktop 的低对比侧栏、宽松消息排版和底部输入区。通信与加密暂时复用独立 Python 核心。

普通用户从 [v2.0.0 发布页](https://github.com/starryuchuu/chatroom/releases/tag/v2.0.0) 下载 Windows / Linux x64 桌面 ZIP，完整解压后运行 `chatroom.exe` / `./chatroom`，无需安装 Python 或 Node.js。升级时关闭旧客户端并保留原配置和独立离线密钥备份；新核心沿用原本机配置与密钥库。先处理旧进程的待确认发送，草稿不跨进程保存。

## 源码运行

需要 Node.js 24、Python 3.11+。在仓库根目录开始：

```bash
python -m pip install -r requirements.txt
cd desktop
npm ci
npm start
```

`npm start` 编译并启动 Electron；`npm run dev` 启用本机 Vite 开发服务器。开发模式默认调用 `python3`（Windows 为 `python`）；使用虚拟环境时先激活环境，或将 `CHATROOM_PYTHON` 设置为解释器的绝对路径。根目录的 `python client.py` 将当前解释器传给 Electron。

首次启动可能下载 Electron 运行时。通过代理联网的 Node.js 24 环境可设置 `NODE_USE_ENV_PROXY=1`，保留代理和受信任 CA 配置。

默认服务器仍为本机 Python 12345 / Go 12346。登录页右上角进入「设置 → 服务器」管理地址、端口和经核实的公钥指纹。远程连接必须固定服务器指纹，连接 / 认证 / 重连期间禁止切换配置。

## 界面入口

- 登录页切换创建账号；「恢复与迁移」提供离线备份导入、旧账号迁移和旧密钥解锁。
- 侧栏按全部 / 好友 / 群聊筛选，点击「新的对话」添加好友或创建群聊。
- 左侧栏底部「在线用户」显示当前服务器在线人数，点击查看和搜索用户名；人数包含自己，列表随服务器推送更新。断线时明确显示为上次列表，避免误报在线。
- Enter 发送，Shift / Ctrl / Command + Enter 换行。中文输入法预编辑 Enter 不触发发送。
- 别人的消息和头像在左侧，自己的消息和头像在右侧；长消息在各自区域内换行。
- Ctrl / Command + F 搜索当前会话已加载且通过验证的正文；搜索、草稿和正文只在内存中保留。
- 消息支持原生文本选择；消息操作可复制全文、查看原始时间和保护状态。
- 阅读历史时不跟随收到的消息；点击「回到最新」返回底部，缓存淘汰时重新请求最新历史。
- 「加密与密钥」显示身份指纹，提供联系人核验、新密钥确认、离线备份、改密和群接收人核验。
- 「更多 → 待确认消息」逐条核对原结果。服务器确认无回执后允许显式重试；移除本机记录需要确认，不撤回服务器消息。
- 深浅主题在设置或聊天页右上角切换，写入原配置文件；退出不删除加密密钥库。

## 打包

在目标系统构建核心，再打包桌面：

```bash
python -m pip install -r requirements-build.txt
pyinstaller --onefile --console --exclude-module tkinter --collect-submodules Crypto.PublicKey --collect-all wasmtime --additional-hooks-dir hooks --add-data "chatroom_client/opaque_core.wasm:chatroom_client" --distpath desktop/core-dist --clean --name chatroom-core core_client.py
cd desktop
npm ci
npm run dist
```

`release/` 输出 Windows / Linux ZIP，内含 Electron 和核心，用户无需安装 Python / Node.js。Windows 解压后运行 `chatroom.exe`；Linux 运行 `./chatroom`。Windows / Linux CI 均检查实际打包客户端。macOS 配置已提供，当前流水线尚不构建 macOS 客户端。

新入口和核心不导入 Tk，桌面分发包不包含旧视图。旧 Tk 源码与测试暂留仓库，作为迁移期间的历史回归基准。

发布隐私检查允许更大的单一归档成员以容纳 Electron，但保持总展开预算。Electron 45.0.0 Linux / Windows x64 官方二进制包含公开构建路径；只有与已核验官方 ZIP 中程序 SHA-256 完全一致的原始字节才豁免通用个人路径启发式。配置的禁止值、密钥和凭据检查仍执行，修改或追加字节立即失去豁免。升级 Electron 必须重新核验，不能扩大通用用户名白名单。

Windows 设置 `signAndEditExecutable: false`，保留原始 Electron 程序字节与上游资源信息，不改写 EXE 图标和文件属性，也不额外签名；Chatroom 版本来自应用包的 `package.json`。未来加入品牌资源或签名时，需重新设计相应的上游路径校验，不能对已修改 EXE 套用原文件的哈希豁免。

## 验证

```bash
# 根目录：真实服务端上的双核心 E2EE 测试
python -m unittest discover -s tests -p test_desktop_rpc.py -v
# 设置 CHATROOM_GO_SERVER_EXE 可同时覆盖 Go 服务端
cd desktop
npm run build
npm test
# Linux 无显示环境：xvfb-run -a npm test
```

`CHATROOM_DESKTOP_EXECUTABLE` 指向解包客户端的绝对路径时，同一 Playwright 套件检查打包产物。渲染测试使用隔离配置与虚构数据；真实中文输入法候选窗口和预编辑体验仍需目标系统人工验证。

## 发布

日常推送只运行受改动影响的检查；完整跨平台测试和成品打包仅在正式标签发布时执行。在干净且包含发布说明的 `master` 上运行 `python scripts/release.py <新版本>`，或加 `--dry-run` 预览。步骤及失败重试见[贡献指南](../CONTRIBUTING.md)。

## Rust 替换边界

Electron 只启动核心并转发 JSON-RPC，不调用 Python 模块。未来 Rust 核心实现 [Desktop Protocol v1](DESKTOP_PROTOCOL.md) 和 [`protocol.ts`](../desktop/src/protocol.ts) 后，可替换相同位置的核心程序，复用全部界面。

替换时保持账号 / socket / 群代次、确认上下文、密钥库兼容与发送幂等语义，并运行相同的 Python / Go 服务端互操作测试。本次 UI 迁移不修改服务器线协议和加密格式。
