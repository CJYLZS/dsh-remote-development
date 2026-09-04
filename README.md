# dsh-remote-development

English | [中文](README.zh.md)

## Summary

This plugin adds lightweight remote development to DeepSeek Harness: you register an SSH machine, pick a remote directory as the session's workspace, and the agent then works on that remote workspace with the SAME tools it uses locally — file tools, shell, and search. The plugin does not add any model-facing tool and no third-party UI plugin: it replaces the filesystem, subprocess, and bash providers with routing versions that translate local tool calls into remote execution over SSH, and it contributes one settings section plus one workspace directory-flow dialog in the Web GUI.

## Table of Contents

- [Use this plugin](#use-this-plugin)
- [Understand the design](#understand-the-design)
- [Configuration](#configuration)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="use-this-plugin"></a>
## Use this plugin

Install straight from GitHub — the built `lib/` is committed, so no build step is needed:

```sh
dsh plugin add --profile web github:CJYLZS/dsh-remote-development
```

To develop the plugin from a local checkout instead, build first and add the checkout path:

```sh
cd dsh-remote-development
pnpm install          # self-contained workspace; store lives in .pnpm-store/
pnpm run build        # emits lib/index.js (host) and lib/client.js (browser)
dsh plugin add --profile web link:/absolute/path/to/dsh-remote-development
```

The `link:` install points the profile at the checkout directory, so later `pnpm run build` runs apply on the next harness restart without re-adding.

### First install: ssh2's build script

pnpm ≥ 10 blocks dependency build scripts by default, and a GitHub install brings `ssh2` into the profile's workspace fresh, so the first `dsh plugin add` can fail with `[ERR_PNPM_IGNORED_BUILDS] Ignored build scripts: cpu-features@…, ssh2@…`. Decide both keys once under the existing `allowBuilds` map in the profile's `pnpm-workspace.yaml` (`~/.dsh/profiles/<profile>/pnpm-workspace.yaml`) and re-run the add command:

```yaml
allowBuilds:
  cpu-features: false
  ssh2: false
```

`false` is the safe choice: ssh2's install script only probes an optional native acceleration (cpu-features), and ssh2 runs fully on its pure-JS fallback without it — no toolchain or network needed at install time. If you want the acceleration and have a build toolchain, use `ssh2: true` instead. No other build scripts are involved.

Restart the harness after installing. The Web GUI then shows:

- a **dsh-remote-development** settings section where you add machines (host, port, username; password, private key, or SSH agent authentication; optional jump proxy) and test them;
- in the workspace directory flow (the hero "choose directory" dialog and the sidebar workspaces picker), a **远程** tab that lists machines, browses remote directories, creates folders, and sets a remote directory as the session workspace.

Setting a remote workspace creates an **anchor** under `$DSH_HOME/remote-workspaces/<host>-<user>-<port>/<basename>` — a real local directory carrying remote coordinates in a metadata file. A session whose working directory is an anchor routes to the remote machine; every other path keeps local behavior, so existing sessions are unaffected.

While a session sits on an anchor, the model is told (one system-prompt section) that its workspace is remote and that the usual tools operate there directly.

-----

<a id="understand-the-design"></a>
## Understand the design

Three routing providers replace the base row of the same service, so every local tool keeps working and only the transport changes:

- `RoutingFileSystem` (replaces the sandbox filesystem) — file reads, writes, edits, and listings whose path resolves to a remote root go through SFTP; everything else delegates to the local base via `super()`.
- `RoutingSubprocessRuntime` (replaces the local subprocess runtime) — spawns with an anchor cwd execute on the remote host over an SSH exec channel; the packaged ripgrep used by search tools is rewritten to the remote `rg` binary.
- `RoutingBashExecutor` (replaces the sandbox bash executor, POSIX hosts only) — bash scripts run through `bash -c` on the remote host; background processes get a real remote PID via a process-group kill protocol.
- **One shared SFTP session per machine.** The SFTP protocol multiplexes every request over one subsystem channel, so all file operations share a single session instead of opening (and leaking) a channel per call — servers cap sessions per connection, and exhausted caps answer every open with a channel failure.

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
- **Persistent terminal sessions are not supported.** The terminal tool reports an explicit "not supported by dsh-remote-development" error instead of letting the agent try; use the bash tool for remote commands.
- **`@` file references are not supported in remote sessions.** Typing `@` in a remote session yields a single explicit "not supported yet" candidate rather than a silent failure; the reference-source interface is reserved for a later phase.
- **No mirror or sync layer.** Anchor directories hold metadata only, not file copies; every read and write crosses SSH, bounded by `maxFileBytes`.
- **Search needs a remote ripgrep.** The `rg` binary must exist on the remote machine (configurable via `remoteRipgrep`); otherwise search tools fail on remote paths.
- **Not published to npm.** Install from GitHub (`dsh plugin add --profile web github:CJYLZS/dsh-remote-development`) or from a local checkout path; the GitHub install uses the committed `lib/` build, while a local path links the directory so rebuilds apply on restart.
- **The built-in directory-picker flow is shadowed, not replaced.** Both directory-flow registrations coexist at distinct priorities (this plugin uses -1, lowest renders); unloading this plugin hands the slot back to the built-in picker.

-----

<a id="dev-note"></a>
## Dev Note

The plugin directory is a self-contained pnpm workspace (`packages: [- .]`, `storeDir: .pnpm-store`) so pnpm cannot reach the harness repository's workspace. dsh framework packages are declared as `peerDependencies` (^0.1.2-rc.1, supplied by the host profile) and pinned exactly in `devDependencies` for local types and builds; no relative `link:` dependencies exist inside the dependency graph, so the directory builds standalone in any location.

Commands: `pnpm run build` (tsdown, both halves), `pnpm run typecheck`, `pnpm run test` (node:test via tsx; no SSH server needed — the pool accepts an injected client factory and the SFTP surface is faked).
