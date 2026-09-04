---
description: "DeepSeek Harness 的远程开发插件：通过 SSH 选择远程工作区，让 agent 用与本地相同的工具在其中工作；面向需要操作远程机器的用户。"
kind: "package-reference"
---

# dsh-remote-development

[English](README.md) | 中文

## 摘要

本插件为 DeepSeek Harness 提供轻量化远程开发：注册一台 SSH 机器，把远程目录选为会话工作区之后，agent 即可用与本地完全相同的工具（文件工具、shell、搜索）在该远程工作区上工作。插件不新增任何面向模型的工具，也不引入第三方 UI 插件：它把文件系统、子进程、bash 三个 provider 替换为路由版本，将本地工具调用翻译为经 SSH 的远程执行；同时在 Web GUI 中贡献一个设置分区和一个工作区目录选择对话框。

## 目录

- [使用本插件](#使用本插件)
- [理解设计](#理解设计)
- [配置](#配置)
- [已知限制与延期工作](#已知限制与延期工作)
- [开发说明](#开发说明)

-----

<a id="使用本插件"></a>
## 使用本插件

插件是树外目录（不是 npm 包），先构建再从路径安装：

```sh
cd lib/dsh-remote-development
pnpm install          # 自包含 workspace；store 位于 .pnpm-store/
pnpm run build        # 产出 lib/index.js（宿主半）与 lib/client.js（浏览器半）

dsh plugin add --profile web link:/absolute/path/to/lib/dsh-remote-development
```

之后重启 harness。Web GUI 中会出现：

- **dsh-remote-development** 设置分区：添加机器（host、port、用户名；密码、私钥或 SSH agent 认证；可选跳板机）并测试连接；
- 工作区目录流（hero 的"选择目录"对话框与侧边栏工作区选择器）中的**远程**标签页：列出机器、浏览远程目录、新建文件夹，并把远程目录设为会话工作区。

设置远程工作区会在 `$DSH_HOME/remote-workspaces/<host>-<user>-<port>/<basename>` 下创建一个**锚点**——一个携带远程坐标元数据文件的真实本地目录。会话工作目录落在锚点上即路由到远程机器；其余路径保持本地行为，既有会话不受影响。

会话位于锚点时，模型会通过一个 system-prompt 分区获知：工作区是远程的，常用工具在其中直接生效。

-----

<a id="理解设计"></a>
## 理解设计

三个路由 provider 替换同一服务的基座行，所有本地工具继续可用，只有传输层改变：

- `RoutingFileSystem`（替换沙箱文件系统）——路径解析到远程根的读写、编辑、列目录经 SFTP 完成；其余调用经 `super()` 委托本地基座。
- `RoutingSubprocessRuntime`（替换本地子进程运行时）——以锚点为 cwd 的 spawn 在远程主机上经 SSH exec 通道执行；搜索工具使用的打包 ripgrep 会被改写为远程 `rg` 二进制。
- `RoutingBashExecutor`（替换沙箱 bash 执行器，仅 POSIX 宿主）——bash 脚本经远程 `bash -c` 执行；后台进程通过进程组 kill 协议拿到真实远程 PID。
- **每机器一条共享 SFTP 会话。** SFTP 协议在单一子系统通道上多路复用所有请求，全部文件操作共享一条会话，而不是每次调用开一条（并泄漏）通道——服务器对单连接的会话数有上限，耗尽后所有打开请求都以通道失败告终。

**模型看不到锚点句柄。** harness 的系统提示会报告会话工作目录；远程会话下插件按 agent 覆盖该变量为远程路径，模型可见的 `cwd` 即命令真正运行的目录。作为兜底，命令文本中的锚点目录写法（绝对路径、`~`、`$HOME`、`${HOME}`）会在执行前改写为远程路径——仅限同机锚点，stdin 保持原样。本地会话不受影响。

远程变更策略与本地沙箱一致：read-only 模式拒绝远程写入；workspace-write 仅允许写远程工作区根与远程 `/tmp`。远程写入按文件串行化、原子发布（临时文件 + rename），并对过期版本与歧义编辑返回与本地文件系统相同的错误码。

主机密钥采用 TOFU（默认 `accept-new`）：首次见到的密钥被记录，变更的密钥以中间人原因拒绝；每台机器可选 `verify`/`off` 模式。

-----

<a id="配置"></a>
## 配置

机器在设置分区中管理；插件自身通过 cordis.yml 接受配置默认值（均可选）：

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `commandTimeoutMs` | 20000 | 单命令超时；SIGTERM 宽限后关闭通道。 |
| `connectTimeoutMs` | 15000 | SSH 连接建立超时。 |
| `maxOutputChars` | 200000 | 超出后命令输出保留头尾。 |
| `maxFileBytes` | 52428800 | SFTP 单次读写的最大文件体积。 |
| `hostKeyMode` | `accept-new` | `accept-new`、`verify` 或 `off`。 |
| `remoteRipgrep` | `rg` | 打包 ripgrep 改写到的远程二进制。 |
| `anchorRoot` | `$DSH_HOME/remote-workspaces` | 锚点目录的根目录。 |
| `auditLog` | 关闭 | 远程执行的追加式 JSONL 审计。 |

-----

<a id="已知限制与延期工作"></a>
## 已知限制与延期工作

- **Windows 远程机延期支持。** 远程机器必须运行 POSIX shell；`uname` 探测会以明确错误拒绝 Windows 目标。适配预留到后续阶段。
- **不支持持久终端会话。** 终端工具会返回明确的"not supported by dsh-remote-development"错误，而不是让 agent 自行尝试；远程命令请使用 bash 工具。
- **远程会话不支持 `@` 文件引用。** 远程会话中输入 `@` 会给出单条明确的"暂不支持"候选，而不是静默失败；引用源接口已预留到后续阶段。
- **没有镜像或同步层。** 锚点目录只保存元数据，不保存文件副本；每次读写都经 SSH，受 `maxFileBytes` 限制。
- **搜索依赖远程 ripgrep。** 远程机器上必须存在 `rg` 二进制（可用 `remoteRipgrep` 配置）；否则搜索工具在远程路径上失败。
- **不发布 npm。** 通过 `dsh plugin add` 从本地路径安装；profile 以链接方式引用目录，添加前必须已构建出 `lib/`。
- **内建目录选择流是被覆盖而非替换。** 两个目录流注册以不同优先级共存（本插件使用 -1，最低者优先渲染）；卸载本插件后槽位交还给内建选择器。

-----

<a id="开发说明"></a>
## 开发说明

插件目录是自包含的 pnpm workspace（`packages: [- .]`、`storeDir: .pnpm-store`），阻断 pnpm 向上探测 harness 仓库的 workspace。dsh 框架包声明为 `peerDependencies`（^0.1.2-rc.1，由宿主 profile 提供），并在 `devDependencies` 中精确锁同版本用于本地类型与构建；依赖图内不存在相对 `link:` 依赖，因此该目录可在任意位置独立构建。

命令：`pnpm run build`（tsdown，双半）、`pnpm run typecheck`、`pnpm run test`（node:test 经 tsx；无需 SSH 服务器——连接池接受注入的 client 工厂，SFTP 表面使用假件）。
