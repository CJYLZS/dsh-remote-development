# dsh-remote-development

[English](README.md) | 中文

## 摘要

本插件为 DeepSeek Harness 提供轻量化远程开发：注册一台 SSH 机器，把远程目录选为会话工作区之后，agent 即可用与本地完全相同的工具（文件工具、shell、搜索）在该远程工作区上工作。插件不新增任何面向模型的工具，也不引入第三方 UI 插件：它把文件系统、子进程、bash 三个 provider 替换为路由版本，将本地工具调用翻译为经 SSH 的远程执行；同时在 Web GUI 中贡献一个设置分区和一个工作区目录选择对话框。

<a id="核心特性"></a>
## 核心特性

- **同构工具集。** 远程工作区不增加任何工具调用：agent 的工具集与本地工作区完全一致，由插件在底层把调用翻译为远程执行。
- **远程零依赖。** 远程机器不需要任何额外的服务端，一条 SSH 连接即可使用。
- **Web GUI 集成。** 连接管理覆盖密码 / 私钥 / SSH agent、跳板机、主机密钥 TOFU 与连接测试；支持为不同远程工作区设置自定义颜色标记。

## 目录

- [核心特性](#核心特性)
- [安装](#安装)
- [使用](#使用)
- [理解设计](#理解设计)
- [配置](#配置)
- [已知限制与延期工作](#已知限制与延期工作)
- [开发说明](#开发说明)
  - [第三方代码](#第三方代码)

-----

<a id="安装"></a>
## 安装

推荐直接从 GitHub 安装——`lib/` 构建产物已入库，一条命令即可，无需构建：

```sh
dsh plugin add --profile web github:CJYLZS/dsh-remote-development
```

开发模式则链接本地检出：

```sh
cd dsh-remote-development
pnpm install          # 自包含 workspace；store 位于 .pnpm-store/
pnpm run build        # 产出 lib/index.js（宿主半）与 lib/client.js（浏览器半）
dsh plugin add --profile web link:/absolute/path/to/dsh-remote-development
```

`link:` 安装把 profile 指向检出目录，之后每次 `pnpm run build` 重启 harness 即生效，无需重新 add。

安装后重启 harness。

<a id="使用"></a>
## 使用

只需三步：

1. **添加机器。** 在 Web GUI 的 **dsh-remote-development** 设置分区填入 host、port、用户名，选择密码 / 私钥 / SSH agent 认证（可选跳板机），点击测试连接。
2. **选择远程目录。** 在工作区目录流（hero 的「选择目录」对话框或侧边栏工作区选择器）打开**远程**页签，浏览机器目录，把某个远程目录设为会话工作区。
3. **照常工作。** 到此为止。文件工具、shell、bash、搜索仍以同样的调用方式执行，只是落在远程机器上；模型的工作目录就是远程路径，不需要任何额外说明，也不会多出任何新工具。所选目录之外的路径保持本地行为，既有会话不受影响。

其底层机制：设置远程工作区会在 `$DSH_HOME/remote-workspaces/<host>-<user>-<port>/<basename>` 下创建一个**锚点**——一个真实本地目录，元数据记录远程坐标。不存在「当前机器」或默认目标，锚点独自决定其会话工具的执行位置。若该机器随后被删除，工作区上的操作会以明确的「机器已失配（no longer configured）」错误失败，而不是悄悄换到别的机器执行——重新添加机器即可恢复，或删除该工作区目录。

-----

<a id="理解设计"></a>
## 理解设计

三个路由 provider 替换同一服务的基座行，所有本地工具继续可用，只有传输层改变：

- `RoutingFileSystem`（替换沙箱文件系统）——路径解析到远程根的读写、编辑、列目录经 SFTP 完成；其余调用经 `super()` 委托本地基座。
- `RoutingSubprocessRuntime`（替换本地子进程运行时）——以锚点为 cwd 的 spawn 在远程主机上经 SSH exec 通道执行；搜索工具使用的打包 ripgrep 会被改写为远程 `rg` 二进制。路由只看工作目录，所有宿主平台行为一致。
- `RoutingBashExecutor` / `RoutingPwshExecutor`（替换沙箱 bash/pwsh 执行器）——工作目录在锚点下的命令经远程 `bash -c` 执行；后台进程通过进程组 kill 协议拿到真实远程 PID。宿主平台决定挂载哪个执行器——只有**本地回退**与平台相关（POSIX 用本地 bash，Windows 用本地 pwsh）；远程方言始终由远程主机的 POSIX shell 决定。
- **按 agent 的工具可见性。** patch 同时挂载两套 shell 工具栈，并按会话安装作用域限制，隐藏该会话工作区不应使用的方言：远程会话只见 `bash` 工具（不见 `pwsh`），Windows 本机会话只见 `pwsh`（不见插件补入的 `bash`）。POSIX 本机会话两个世界都用 `bash`，与基础组合一致。
- **每机器一条共享 SFTP 会话。** SFTP 协议在单一子系统通道上多路复用所有请求，全部文件操作共享一条会话，而不是每次调用开一条（并泄漏）通道——服务器对单连接的会话数有上限，耗尽后所有打开请求都以通道失败告终。
- **远程工作区在文件树中有标记。** client 会为远程工作区重新着色文件夹图标：host 将每个锚点与其机器的标记颜色（`Machine` 字段，可在设置中编辑）联接，client 把这份清单转成文件树 `data-files-*` 钩子上的属性选择器并以样式表注入。每台机器一个颜色；留空则回退到主题强调色。侧边栏的工作区行没有数据钩子，其规则经行内 `aria-label`（`:has()`）命中，匹配锚点工作区采用目录基名得到的标题。

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
- **Windows 本机支持远程 shell 路由。** Windows 宿主挂载基于 pwsh 的路由执行器：本地工作目录保持沙箱 pwsh 执行器，锚点工作目录跨到远程主机的 bash。模型在远程会话看到 `bash` 工具，本地会话看到 `pwsh` 工具。
- **不支持持久终端会话。** 终端工具会返回明确的"not supported by dsh-remote-development"错误，而不是让 agent 自行尝试；远程命令请使用 bash 工具。持久 shell 工具仍仅限本地：指向远程工作区的持久工具会以同样错误拒绝。
- **远程会话不支持 `@` 文件引用。** 远程会话中输入 `@` 会给出单条明确的"暂不支持"候选，而不是静默失败；引用源接口已预留到后续阶段。
- **没有镜像或同步层。** 锚点目录只保存元数据，不保存文件副本；每次读写都经 SSH，受 `maxFileBytes` 限制。
- **文件树标记依赖 in-box 的 `data-files-*` 钩子。** 着色目标是文件树的数据属性，它们不是声明过的公开契约；dsh 若重命名这些属性，着色会静默消失（纯展示层，不影响其他功能）。工作区行的标记还依赖工作区标题匹配：重命名工作区、或 dsh 更改侧边栏 `aria-label` 文案，会让行标记失效（文件树标记不受影响）。
- **SSH 走纯 JS 而非原生加密。** 打包的 `ssh2` 不会加载可选原生加速件，大文件 SFTP 传输的吞吐低于原生构建版本。
- **搜索依赖远程 ripgrep。** 远程机器上必须存在 `rg` 二进制（可用 `remoteRipgrep` 配置）；否则搜索工具在远程路径上失败。
- **不发布 npm。** 从 GitHub 或本地检出安装，见[安装](#安装)。
- **内建目录选择流是被覆盖而非替换。** 两个目录流注册以不同优先级共存（本插件使用 -1，最低者优先渲染）；卸载本插件后槽位交还给内建选择器。
- **「本机」页签跟随宿主组合的 picker 能力。** 宿主在启动时解析一次目录选择器后端：WSL 缺少 zenity/kdialog、经 SSH 启动、绑定非回环地址或无显示会话的 Linux 都会组合出 `browse` 后端（只有 `list`/`createDirectory` 原语，没有 OS 选择器）。插件的「本机」页签据此分流——`native` 打开 OS 选择器，`browse` 改用宿主的网页目录浏览器；在此之前的版本「本机」页签硬编码 `pick`，在这类启动下会以 `directory-picker/unavailable` 失败。
- **删除机器后其工作区被有意搁置。** 锚点在机器删除后仍然存在，所有工具面对它都会以同样的「机器已失配」错误拒绝（fs、bash、subprocess，提示词的 `cwd` 变量回退为本地句柄），而不是换一台机器或在本机执行。

-----

<a id="开发说明"></a>
## 开发说明

插件目录是自包含的 pnpm workspace（`packages: [- .]`、`storeDir: .pnpm-store`），阻断 pnpm 向上探测 harness 仓库的 workspace。dsh 框架包声明为 `peerDependencies`（^0.1.2-rc.1，由宿主 profile 提供），并在 `devDependencies` 中精确锁同版本用于本地类型与构建；依赖图内不存在相对 `link:` 依赖，因此该目录可在任意位置独立构建。

命令：`pnpm run build`（tsdown，双半）、`pnpm run typecheck`、`pnpm run test`（node:test 经 tsx；无需 SSH 服务器——连接池接受注入的 client 工厂，SFTP 表面使用假件）。

`ssh2` 位于 `devDependencies`，因为它是构建输入而非运行时依赖：`pnpm run build` 会把它打进 `lib/index.js`。任何源码改动都要连同重新构建的 `lib/` 一起提交，否则 GitHub 安装拿到的是旧代码。

<a id="第三方代码"></a>
### 第三方代码

`lib/index.js` 内含 `ssh2`（MIT）、`asn1`（MIT）、`safer-buffer`（MIT）、`tweetnacl`（Unlicense）、`bcrypt-pbkdf`（BSD-3-Clause）的打包副本，许可证全文见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

打包把安全更新的责任移到了本仓库：`ssh2` 的安全公告不再经用户自己的 `pnpm update` 到达他们。修补方式是 `pnpm update ssh2 && pnpm run build`，然后把结果提交到这里。
