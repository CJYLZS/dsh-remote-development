/**
 * The workspace directory-flow occupant: fills ui-workspace's two
 * directory-flow holes with one dialog covering both worlds — 本机 reuses the
 * host picker service, 远程 browses the remote machine over the plugin's JSON
 * routes and commits an anchor workspace.
 * @module dsh-remote-development/client/flow
 */

import { createElement, useCallback, useEffect, useState } from 'react'
import type { ReactElement } from 'react'
import { Button, Input } from '@deepseek-ai/dsh-client-ui-primitives'
import type { Translate } from '@deepseek-ai/dsh-client-ui-slots'
import type { DirectoryFlowOwnerProps } from '@deepseek-ai/dsh-client-ui-workspace/client'
import type { ClientMachine, PickerKind, RemoteEntry } from './api.ts'
import * as api from './api.ts'

/** One local directory row as the host browse primitives report it. */
interface LocalEntry {
  name: string
  path: string
  hidden: boolean
}

/** One local listing level: structural face of the host's DirectoryListing. */
interface LocalListing {
  path: string
  home: string
  crumbs: LocalEntry[]
  entries: LocalEntry[]
  truncated: boolean
}

/**
 * The composed picker interaction, probed once per page: the host resolves
 * the seam at boot, so the answer is stable for the page's lifetime.
 */
let cachedPickerKind: 'native' | 'browse' | null = null

/** Injected face bound in the plugin's apply closure. */
export interface FlowInjected {
  pickLocal: () => Promise<string | null>
  /** List one local directory level (absent path = the host home). */
  listLocalDir: (path?: string) => Promise<LocalListing>
  /** Create one child directory under an existing local parent. */
  createLocalDir: (path: string, name: string) => Promise<string>
  /** Which interaction the host's composed directory picker serves. */
  pickerKind: () => Promise<{ kind: PickerKind }>
  listMachines: typeof api.listMachines
  listRemoteDir: typeof api.listRemoteDir
  createRemoteDir: typeof api.createRemoteDir
  createAnchor: typeof api.createAnchor
  t: Translate
}

type Tab = 'local' | 'remote'
type LocalKind = 'probing' | 'native' | 'browse'

const FOLDER_ICON = createElement('span', { className: 'rdv-itemIcon', 'aria-hidden': true },
  createElement('svg', { width: 14, height: 14, viewBox: '0 0 16 16', fill: 'none' },
    createElement('path', {
      d: 'M1.5 4.5A1.5 1.5 0 0 1 3 3h3l1.5 1.5H13A1.5 1.5 0 0 1 14.5 6v5A1.5 1.5 0 0 1 13 12.5H3A1.5 1.5 0 0 1 1.5 11v-6.5Z',
      stroke: 'currentColor', 'stroke-width': 1.2,
    })))

/**
 * The unified picker dialog. Renders nothing while the flow is closed.
 * @param props - owner conversation plus the injected picking face.
 * @returns the dialog element.
 */
export function RemoteFlow(props: DirectoryFlowOwnerProps & FlowInjected): ReactElement {
  const { open, busy, onPicked, onCancel, onError, t } = props
  const [tab, setTab] = useState<Tab>('local')
  const [machines, setMachines] = useState<ClientMachine[]>([])
  const [machineId, setMachineId] = useState('')
  const [path, setPath] = useState('')
  const [entries, setEntries] = useState<RemoteEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [mkdirOpen, setMkdirOpen] = useState(false)
  const [mkdirName, setMkdirName] = useState('')
  // 本机 tab: the interaction follows the host's composed picker capability —
  // native opens the OS chooser, browse drives the host's list/create
  // primitives in-app (the only servable verbs on a WSL/SSH/headless boot).
  const [localKind, setLocalKind] = useState<LocalKind>(cachedPickerKind ?? 'probing')
  const [localPath, setLocalPath] = useState('')
  const [localCrumbs, setLocalCrumbs] = useState<LocalEntry[]>([])
  const [localEntries, setLocalEntries] = useState<LocalEntry[]>([])
  const [localLoading, setLocalLoading] = useState(false)
  const [localBooted, setLocalBooted] = useState(false)
  const [localMkdirOpen, setLocalMkdirOpen] = useState(false)
  const [localMkdirName, setLocalMkdirName] = useState('')

  const loadMachines = useCallback((): void => {
    void props.listMachines().then((r) => {
      setMachines(r.machines)
      // No "current machine" exists any more: the dropdown preselects the
      // first saved machine and the operator's explicit choice in this
      // dialog is the only thing that directs execution.
      const preferred = r.machines[0]
      if (preferred) {
        setMachineId((prev) => (r.machines.some((m) => m.id === prev) ? prev : preferred.id))
      }
    }).catch((err: Error) => setError(err.message))
  }, [props])

  const loadDir = useCallback((target: string): void => {
    if (!machineId) return
    setLoading(true)
    setError('')
    void props.listRemoteDir(machineId, target).then((r) => {
      setLoading(false)
      if (!r.ok) {
        setError(r.error ?? t('picker.loading'))
        return
      }
      setPath(r.path)
      setEntries(r.entries)
    }).catch((err: Error) => {
      setLoading(false)
      setError(err.message)
    })
  }, [machineId, props, t])

  useEffect(() => {
    if (open && tab === 'remote') loadMachines()
  }, [open, tab, loadMachines])

  useEffect(() => {
    if (open && tab === 'remote' && machineId && !path) loadDir('~')
  }, [open, tab, machineId, path, loadDir])

  const loadLocalDir = useCallback((target?: string): void => {
    setLocalLoading(true)
    setError('')
    void props.listLocalDir(target).then((r) => {
      setLocalLoading(false)
      setLocalPath(r.path)
      setLocalCrumbs(r.crumbs)
      setLocalEntries(r.entries)
    }).catch((err: Error) => {
      setLocalLoading(false)
      setError(err.message)
    })
  }, [props])

  // Probe the composed picker interaction once per page when the 本机 tab is
  // first opened; an unknown seam keeps the previous OS-chooser affordance.
  useEffect(() => {
    if (!open || tab !== 'local') return
    if (cachedPickerKind) {
      setLocalKind(cachedPickerKind)
      return
    }
    let cancelled = false
    void props.pickerKind().then((r) => {
      if (cancelled) return
      if (r.kind === 'browse' || r.kind === 'native') cachedPickerKind = r.kind
      setLocalKind(r.kind === 'browse' ? 'browse' : 'native')
    }).catch(() => {
      if (!cancelled) setLocalKind('native')
    })
    return () => { cancelled = true }
  }, [open, tab, props])

  // Browse mode lists the host home as its first level (boot once, no retry loop).
  useEffect(() => {
    if (open && tab === 'local' && localKind === 'browse' && !localBooted) {
      setLocalBooted(true)
      loadLocalDir()
    }
  }, [open, tab, localKind, localBooted, loadLocalDir])

  if (!open) return createElement('div', { style: { display: 'contents' } })

  const chooseLocal = (): void => {
    void props.pickLocal().then((picked) => {
      if (picked) onPicked(picked)
    }).catch((err: Error) => {
      if (err.message) onError(err.message)
    })
  }

  const commit = (): void => {
    setCreating(true)
    setError('')
    void props.createAnchor(machineId, path).then((r) => {
      setCreating(false)
      if (r.ok) onPicked(r.anchorPath)
      else setError(r.error ?? '')
    }).catch((err: Error) => {
      setCreating(false)
      setError(err.message)
    })
  }

  const mkdir = (): void => {
    void props.createRemoteDir(machineId, path, mkdirName.trim()).then((r) => {
      if (r.ok) {
        setMkdirOpen(false)
        setMkdirName('')
        loadDir(r.path)
      } else {
        setError(r.error ?? '')
      }
    }).catch((err: Error) => setError(err.message))
  }

  /** Jump to the listed directory's parent through its breadcrumb ancestry. */
  const upLocal = (): void => {
    const parent = localCrumbs.length >= 2 ? localCrumbs[localCrumbs.length - 2] : null
    if (parent) loadLocalDir(parent.path)
  }

  const localMkdir = (): void => {
    void props.createLocalDir(localPath, localMkdirName.trim()).then((created) => {
      setLocalMkdirOpen(false)
      setLocalMkdirName('')
      loadLocalDir(created)
    }).catch((err: Error) => setError(err.message))
  }

  const commitLocal = (): void => {
    if (localPath) onPicked(localPath)
  }

  return createElement('div', {
    className: 'rdv-dialog',
    role: 'dialog',
    'aria-modal': true,
    'aria-label': t('picker.title'),
    onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Escape') onCancel() },
  },
    createElement('div', { className: 'rdv-sheet' },
      createElement('div', { className: 'rdv-sheetHead' },
        createElement('div', { className: 'rdv-tabs', role: 'tablist' },
          createElement('button', {
            type: 'button', role: 'tab', 'aria-selected': tab === 'local',
            className: `rdv-tab${tab === 'local' ? ' rdv-tabActive' : ''}`,
            onClick: () => setTab('local'),
          }, t('picker.tabLocal')),
          createElement('button', {
            type: 'button', role: 'tab', 'aria-selected': tab === 'remote',
            className: `rdv-tab${tab === 'remote' ? ' rdv-tabActive' : ''}`,
            onClick: () => setTab('remote'),
          }, t('picker.tabRemote')),
        ),
        createElement('div', { className: 'rdv-spacer' }),
      ),
      tab === 'local'
        ? localKind === 'browse'
          ? createElement('div', { className: 'rdv-sheetBody' },
              createElement('p', { className: 'rdv-hint' }, t('picker.localHint')),
              createElement('div', { className: 'rdv-toolbar' },
                createElement(Input, {
                  className: 'rdv-pathInput',
                  value: localPath,
                  onChange: (e: React.ChangeEvent<HTMLInputElement>) => setLocalPath(e.target.value),
                  onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter') loadLocalDir(localPath) },
                  placeholder: '/home/dev/project',
                  spellCheck: false,
                  autoComplete: 'off',
                  'aria-label': t('picker.path'),
                }),
                createElement(Button, { size: 'sm', onClick: () => loadLocalDir() }, t('picker.home')),
                localCrumbs.length >= 2 && createElement(Button, { size: 'sm', onClick: upLocal }, t('picker.up')),
                createElement(Button, { size: 'sm', onClick: () => loadLocalDir(localPath) }, t('picker.refresh')),
              ),
              createElement('div', { className: 'rdv-list', role: 'listbox' },
                localLoading && createElement('div', { className: 'rdv-empty' }, t('picker.loading')),
                !localLoading && localEntries.length === 0 && createElement('div', { className: 'rdv-empty' }, t('picker.empty')),
                localEntries.map((e) => createElement('button', {
                  key: e.path, type: 'button', role: 'option', className: 'rdv-itemRow',
                  onClick: () => loadLocalDir(e.path),
                },
                  FOLDER_ICON,
                  createElement('span', { className: 'rdv-itemName' }, e.name),
                )),
              ),
              createElement('div', { className: 'rdv-toolbar' },
                localMkdirOpen
                  ? createElement('div', { className: 'rdv-toolbar', style: { flex: 1 } },
                      createElement(Input, {
                        className: 'rdv-pathInput',
                        value: localMkdirName,
                        onChange: (e: React.ChangeEvent<HTMLInputElement>) => setLocalMkdirName(e.target.value),
                        onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter') localMkdir() },
                        placeholder: t('picker.folderName'),
                        autoFocus: true,
                        'aria-label': t('picker.folderName'),
                      }),
                      createElement(Button, { size: 'sm', onClick: localMkdir }, t('picker.create')),
                    )
                  : createElement(Button, { size: 'sm', onClick: () => setLocalMkdirOpen(true) }, t('picker.newFolder')),
              ),
            )
          : createElement('div', { className: 'rdv-sheetBody' },
              createElement('p', { className: 'rdv-hint' }, t('picker.localHint')),
              createElement('div', { className: 'rdv-actions', style: { justifyContent: 'flex-start' } },
                createElement(Button, { variant: 'primary', onClick: chooseLocal }, t('picker.localChoose')),
              ),
            )
        : createElement('div', { className: 'rdv-sheetBody' },
            createElement('p', { className: 'rdv-hint' }, t('picker.remoteHint')),
            machines.length === 0
              ? createElement('div', { className: 'rdv-empty' }, t('settings.noMachines'))
              : createElement('div', { className: 'rdv-toolbar' },
                  createElement('select', {
                    className: 'rdv-select',
                    value: machineId,
                    'aria-label': t('picker.machine'),
                    onChange: (e: React.ChangeEvent<HTMLSelectElement>) => {
                      setMachineId(e.target.value)
                      setPath('')
                      setEntries([])
                    },
                  },
                    machines.map((m) => createElement('option', { key: m.id, value: m.id },
                      `${m.name} (${m.username}@${m.host})`)),
                  ),
                  createElement(Button, { size: 'sm', onClick: () => loadDir('~') }, t('picker.home')),
                  createElement(Button, { size: 'sm', onClick: () => loadDir(path) }, t('picker.refresh')),
                ),
            machines.length > 0 && createElement('div', { className: 'rdv-toolbar' },
              createElement(Input, {
                className: 'rdv-pathInput',
                value: path,
                onChange: (e: React.ChangeEvent<HTMLInputElement>) => setPath(e.target.value),
                onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter') loadDir(path) },
                placeholder: '/home/dev/project',
                spellCheck: false,
                autoComplete: 'off',
                'aria-label': t('picker.path'),
              }),
              createElement(Button, { size: 'sm', onClick: () => loadDir(path) }, t('picker.refresh')),
            ),
            machines.length > 0 && createElement('div', { className: 'rdv-list', role: 'listbox' },
              loading && createElement('div', { className: 'rdv-empty' }, t('picker.loading')),
              !loading && entries.length === 0 && createElement('div', { className: 'rdv-empty' }, t('picker.empty')),
              entries.filter((e) => e.dir).map((e) => createElement('button', {
                key: e.path, type: 'button', role: 'option', className: 'rdv-itemRow',
                onClick: () => loadDir(e.path),
              },
                FOLDER_ICON,
                createElement('span', { className: 'rdv-itemName' }, e.name),
              )),
            ),
            machines.length > 0 && createElement('div', { className: 'rdv-toolbar' },
              mkdirOpen
                ? createElement('div', { className: 'rdv-toolbar', style: { flex: 1 } },
                    createElement(Input, {
                      className: 'rdv-pathInput',
                      value: mkdirName,
                      onChange: (e: React.ChangeEvent<HTMLInputElement>) => setMkdirName(e.target.value),
                      onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter') mkdir() },
                      placeholder: t('picker.folderName'),
                      autoFocus: true,
                      'aria-label': t('picker.folderName'),
                    }),
                    createElement(Button, { size: 'sm', onClick: mkdir }, t('picker.create')),
                  )
                : createElement(Button, { size: 'sm', onClick: () => setMkdirOpen(true) }, t('picker.newFolder')),
            ),
          ),
      error && createElement('div', { className: 'rdv-error', style: { padding: '0 18px 10px' } }, error),
      createElement('div', { className: 'rdv-sheetFoot' },
        createElement('span', { className: 'rdv-status' },
          tab === 'remote' && path ? path
            : tab === 'local' && localKind === 'browse' && localPath ? localPath
              : ''),
        createElement('div', { className: 'rdv-spacer' }),
        createElement(Button, { onClick: onCancel }, t('picker.cancel')),
        tab === 'remote' && createElement(Button, {
          variant: 'primary',
          disabled: busy || creating || loading || !machineId || !path,
          onClick: commit,
        }, creating ? t('picker.committing') : t('picker.commit')),
        tab === 'local' && localKind === 'browse' && createElement(Button, {
          variant: 'primary',
          disabled: busy || localLoading || !localPath,
          onClick: commitLocal,
        }, t('picker.localCommit')),
      ),
    ),
  )
}
