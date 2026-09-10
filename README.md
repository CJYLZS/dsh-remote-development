# dsh-remote-development

English | [中文](README.zh.md)

## Summary

This plugin adds lightweight remote development to DeepSeek Harness: you register an SSH machine, pick a remote directory as the session's workspace, and the agent then works on that remote workspace with the SAME tools it uses locally — file tools, shell, and search. The plugin does not add any model-facing tool and no third-party UI plugin: it replaces the filesystem, subprocess, and bash providers with routing versions that translate local tool calls into remote execution over SSH, and it contributes one settings section plus one workspace directory-flow dialog in the Web GUI.

<a id="highlights"></a>
## Highlights

- **Identical toolset.** Remote workspaces add no tool calls: the agent works with the exact same tools as a local workspace, and the plugin translates those calls to remote execution underneath.
- **Zero remote dependencies.** The remote machine needs no extra server-side component — an SSH connection is all it takes.
- **Web GUI integration.** Connection management covers password / private key / SSH agent, jump hosts, host-key TOFU, and connection testing; remote workspaces can be told apart by a custom per-machine color.

## Table of Contents

- [Highlights](#highlights)
- [Install](#install)
- [Usage](#usage)
- [Understand the design](#understand-the-design)
- [Configuration](#configuration)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)
  - [Third-party code](#third-party-code)

-----

<a id="install"></a>
## Install

From GitHub (recommended) — the built `lib/` is committed, so it is one command with no build step:

```sh
dsh plugin add --profile web github:CJYLZS/dsh-remote-development
```

For development, link a local checkout instead:

```sh
cd dsh-remote-development
pnpm install          # self-contained workspace; store lives in .pnpm-store/
pnpm run build        # emits lib/index.js (host) and lib/client.js (browser)
dsh plugin add --profile web link:/absolute/path/to/dsh-remote-development
```

A `link:` install points the profile at the checkout directory, so later `pnpm run build` runs apply on the next harness restart without re-adding.

Restart the harness after installing.

<a id="usage"></a>
## Usage

Three steps and nothing else:

1. **Add a machine.** In the Web GUI's **dsh-remote-development** settings section, enter host, port, and username, choose password / private key / SSH agent authentication (optional jump proxy), and click test.
2. **Pick a remote directory.** In the workspace directory flow (the hero "choose directory" dialog or the sidebar workspaces picker), open the **Remote** tab, browse the machine's directories, and set one as the session workspace.
3. **Work as usual.** That is the whole setup. File tools, shell, bash, and search run through the same tool calls as before — only now they execute on the remote machine; the model's working directory is the remote path, so it needs no special instructions and gains no new tools. Anything outside the chosen directory keeps local behavior, so existing sessions are untouched.

Under the hood, setting a remote workspace creates an **anchor** under `$DSH_HOME/remote-workspaces/<host>-<user>-<port>/<basename>` — a real local directory whose metadata records the remote coordinates. There is no "current machine" and no default target: the anchor alone decides where its session's tools execute. If that machine is later deleted, operations on the workspace fail with an explicit "machine is no longer configured" error instead of silently running elsewhere — re-add the machine to resume, or delete the workspace directory.

-----

<a id="understand-the-design"></a>
## Understand the design

Three routing providers replace the base row of the same service, so every local tool keeps working and only the transport changes:

- `RoutingFileSystem` (replaces the sandbox filesystem) — file reads, writes, edits, and listings whose path resolves to a remote root go through SFTP; everything else delegates to the local base via `super()`.
- `RoutingSubprocessRuntime` (replaces the local subprocess runtime) — spawns with an anchor cwd execute on the remote host over an SSH exec channel; the packaged ripgrep used by search tools is rewritten to the remote `rg` binary. Routing keys on the workdir alone, so behavior is identical on every host platform.
- `RoutingBashExecutor` / `RoutingPwshExecutor` (replace the sandbox bash/pwsh executor) — commands with a workdir under an anchor run through `bash -c` on the remote host, and background processes get a real remote PID via a process-group kill protocol. The host platform picks which executor mounts — only the LOCAL fallback is platform-bound (local bash on POSIX, local pwsh on Windows); the remote host's POSIX shell always decides the remote dialect.
- **Per-agent tool visibility.** The patch mounts both shell tool stacks, and a scoped restriction per session hides the dialect the session's workspace must not use: a remote session sees the `bash` tool (never `pwsh`), and a local session on a Windows host sees `pwsh` (never the plugin-added `bash`). POSIX local sessions keep `bash` for both worlds, matching the base composition.
- **One shared SFTP session per machine.** The SFTP protocol multiplexes every request over one subsystem channel, so all file operations share a single session instead of opening (and leaking) a channel per call — servers cap sessions per connection, and exhausted caps answer every open with a channel failure.
- **Remote workspaces are marked in the file tree.** The client recolors folder icons for remote workspaces: the host joins every anchor with its machine's marker color (a `Machine` field, editable in settings), and the client turns that list into attribute selectors over the tree's `data-files-*` hooks, injected as a stylesheet. One color per machine; leaving it empty falls back to the theme accent. The sidebar's workspace rows expose no data hooks, so their rules reach the row through its `aria-label`s (`:has()`), matching the workspace title an anchor workspace adopts from its directory basename.

**The model never sees the anchor handle.** The harness's system prompt reports the session's working directory; for a remote session the plugin overrides that variable per agent with the remote path, so the model-visible `cwd` is the directory its commands actually run in. As a safety net, anchor-directory spellings (absolute, `~`, `$HOME`, `${HOME}`) in command text are rewritten to their remote paths before execution — same-machine anchors only, stdin left verbatim. Local sessions pass through unchanged.

Remote mutation policy mirrors the local sandbox: read-only mode rejects remote writes; workspace-write allows writes only under the remote workspace root and the remote `/tmp`. Remote writes are serialized per file, publish atomically (temp file + rename), and refuse stale versions and ambiguous edits with the same error codes the local filesystem produces.

Host keys use TOFU (`accept-new` by default): the first-seen key is recorded, a changed key is rejected with a MITM reason, and `verify`/`off` modes are available per machine.

-----

<a id="configuration"></a>
## Configuration

Machines are managed in the settings section; the plugin itself takes config defaults through cordis.yml (all optional):

| Field | Default | Meaning |
| --- | --- | --- |
| `commandTimeoutMs` | 20000 | Per-command timeout; the channel is closed after SIGTERM grace. |
| `connectTimeoutMs` | 15000 | SSH connection establishment timeout. |
| `maxOutputChars` | 200000 | Command output kept head-plus-tail beyond this size. |
| `maxFileBytes` | 52428800 | Largest file read or written through SFTP. |
| `hostKeyMode` | `accept-new` | `accept-new`, `verify`, or `off`. |
| `remoteRipgrep` | `rg` | Remote binary the packaged ripgrep is rewritten to. |
| `anchorRoot` | `$DSH_HOME/remote-workspaces` | Root directory for anchor directories. |
| `auditLog` | off | Append-only JSONL audit of remote executions. |

-----

<a id="known-limitations-and-deferred-work"></a>
## Known Limitations and Deferred Work

- **Windows remote hosts are deferred.** Remote machines must run a POSIX shell; `uname` detection rejects Windows targets with a clear error. Adaptation is reserved for a later phase.
- **Windows local hosts route remote shell commands.** A Windows host mounts the pwsh-based routing executor: local workdirs keep the sandboxed pwsh executor, and anchor workdirs cross to the remote host's bash. The model sees the `bash` tool for remote sessions and the `pwsh` tool for local ones.
- **Persistent terminal sessions are not supported.** The terminal tool reports an explicit "not supported by dsh-remote-development" error instead of letting the agent try; use the bash tool for remote commands. Persistent shell tools remain local-only: a persistent tool pointed at a remote workspace refuses with the same error.
- **`@` file references are not supported in remote sessions.** Typing `@` in a remote session yields a single explicit "not supported yet" candidate rather than a silent failure; the reference-source interface is reserved for a later phase.
- **No mirror or sync layer.** Anchor directories hold metadata only, not file copies; every read and write crosses SSH, bounded by `maxFileBytes`.
- **Tree marking depends on in-box `data-files-*` hooks.** The recoloring targets the file tree's data attributes, which are not a declared public contract; a dsh rename silently drops the coloring (purely presentational — nothing else breaks). Workspace-row markers additionally match by workspace title: renaming a workspace, or a dsh change to the sidebar's `aria-label` copy, drops the row marker while the file-tree marker keeps working.
- **Search needs a remote ripgrep.** The `rg` binary must exist on the remote machine (configurable via `remoteRipgrep`); otherwise search tools fail on remote paths.
- **SSH runs on pure JS, not native crypto.** The bundled `ssh2` never loads its optional native accelerators, so throughput on large SFTP transfers is lower than a natively-built `ssh2` would give.
- **Not published to npm.** Install from GitHub or a local checkout — see [Install](#install).
- **The built-in directory-picker flow is shadowed, not replaced.** Both directory-flow registrations coexist at distinct priorities (this plugin uses -1, lowest renders); unloading this plugin hands the slot back to the built-in picker.
- **The 本机 (local) tab follows the host's composed picker capability.** The host resolves its directory-picker backend once at boot: a WSL without zenity/kdialog, an SSH launch, a non-loopback bind, or a display-less Linux all compose the `browse` backend (only the `list`/`createDirectory` primitives — no OS chooser). The local tab branches on that resolution — `native` opens the OS chooser, `browse` drives the host's in-app web browser instead; before this, the tab hard-coded `pick`, which fails with `directory-picker/unavailable` on such boots.
- **Deleting a machine strands its workspaces on purpose.** Anchors survive machine deletion, and every tool surface refuses them with the same "no longer configured" error (fs, bash, subprocess, and the prompt's cwd variable falls back to the local handle) rather than executing on another machine or locally.

-----

<a id="dev-note"></a>
## Dev Note

The plugin directory is a self-contained pnpm workspace (`packages: [- .]`, `storeDir: .pnpm-store`) so pnpm cannot reach the harness repository's workspace. dsh framework packages are declared as `peerDependencies` (^0.1.2-rc.1, supplied by the host profile) and pinned exactly in `devDependencies` for local types and builds; no relative `link:` dependencies exist inside the dependency graph, so the directory builds standalone in any location.

Commands: `pnpm run build` (tsdown, both halves), `pnpm run typecheck`, `pnpm run test` (node:test via tsx; no SSH server needed — the pool accepts an injected client factory and the SFTP surface is faked).

`ssh2` is a `devDependency` because it is build input, not a runtime dependency: `pnpm run build` bundles it into `lib/index.js`. Commit the rebuilt `lib/` with any source change, or the GitHub install serves stale code.

<a id="third-party-code"></a>
### Third-party code

`lib/index.js` contains bundled copies of `ssh2` (MIT), `asn1` (MIT), `safer-buffer` (MIT), `tweetnacl` (Unlicense), and `bcrypt-pbkdf` (BSD-3-Clause). Their license texts are reproduced in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Bundling moves security updates onto this repository: an `ssh2` advisory no longer reaches users through their own `pnpm update`. Patching it means `pnpm update ssh2 && pnpm run build`, then committing the result here.
