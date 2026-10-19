# 开发与发布

## 模块职责

| 文件 / 目录 | 职责 |
| --- | --- |
| `client.py` | Tk 界面、后台连接与发送、服务器事件分发 |
| `client_history.py` | 客户端历史同步状态、分页游标、消息排序和群缓存清理 |
| `server.py` | Python 服务端认证、会话与业务操作 |
| `transport.py` | Python 协议 v2 报文认证、方向密钥与序号 |
| `storage.py` | Python 加密存储及旧库迁移 |
| `history_store.py` / `pending_store.py` | 历史分页查询 / 待处理申请持久化 |
| `go-server/internal/` | Go 服务端的协议、存储、业务处理和连接管理 |
| `tests/` | Python、真实 Tk 窗口及 Python / Go 互操作回归 |

客户端后台线程统一通过 `start_worker()` 启动。关闭时先中断网络和发送队列，等待工作线程退出、清理 UI 回调后再由主线程销毁 Tk，避免 Tcl 对象在后台线程被回收。

历史分页只在收到对应会话的 `history_end` 后推进游标。失败时保留原请求游标；已经收到的消息通过 ID 去重。登录快照或其他会话的完成事件不能清除当前分页请求。断线和登录都通过 `reset_history()` 重置会话历史状态。

## 本地验证

使用 Python 3.11+、Go 1.24.5+。Linux 需要 Tk、Xvfb 和 xauth；Windows 在桌面会话中运行，无需 `xvfb-run`。

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

Windows 可使用 `go test -count=1 ./...`，构建 `go-interop-server.exe`，设置 `CHATROOM_GO_SERVER_EXE` 后直接执行 Python 测试。未设置此变量会跳过 Go 互操作测试。测试使用临时数据库；Go 互操作测试需要本机端口 `12346` 空闲。

## 发布

1. 同步更新根目录和 `go-server/` 的 `VERSION`，版本格式为 `vX.Y.Z`。
2. 更新两处 `RELEASE_NOTES.md`，说明修复、兼容性和升级方式。
3. 新增 Python 模块时，更新 README 文件结构及 `.github/workflows/release.yml` 的源码附件与校验文件清单。PyInstaller 会自动收集静态导入的模块。
4. 将验证通过的提交推送到 `master`。版本文件的变更自动触发 `Release Chatroom`。
5. 确认 Windows / Linux 测试、Python 双平台构建及 Go 六平台构建均通过，Release 包含源码、可执行文件和 `SHA256SUMS`。

发布工作流在测试成功后构建，并由最终发布任务创建指向该提交的版本标签和 GitHub Release。
