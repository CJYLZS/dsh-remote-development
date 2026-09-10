/**
 * The settings page: the saved-machine registry (add, edit, test, delete).
 * Pure presentation — every fact and callback arrives through the props
 * shares. Machines are standby connection records only: which machine serves
 * a workspace is decided by that workspace's anchor, so there is no
 * "current machine" to pick here.
 * @module dsh-remote-development/client/settings
 */

import { Fragment, createElement, useCallback, useEffect, useState } from 'react'
import type { ReactElement } from 'react'
import { Button, Input, Modal } from '@deepseek-ai/dsh-client-ui-primitives'
import type { Translate } from '@deepseek-ai/dsh-client-ui-slots'
// Type-only: the settings section owner-share declaration.
import type { SettingsSectionOwnerProps } from '@deepseek-ai/dsh-client-ui-settings/client'
import type { ClientMachine } from './api.ts'

/** Injected face bound in the plugin's apply closure. */
export interface SettingsInjected {
  listMachines: () => Promise<{ machines: ClientMachine[] }>
  saveMachine: (machine: Record<string, unknown>) => Promise<{ machine: ClientMachine }>
  deleteMachine: (id: string) => Promise<{ ok: boolean }>
  testConnection: (machine: Record<string, unknown>) => Promise<{ ok: boolean; error?: string; platform?: string }>
  /** Re-read the anchors and recolor the workspace tree's remote markers. */
  refreshTreeMark: () => Promise<void>
  t: Translate
}

/** Draft machine being added or edited. */
interface Draft {
  id: string
  name: string
  host: string
  port: string
  username: string
  auth: 'password' | 'key' | 'agent'
  password: string
  /** Whether the machine being edited has a stored password (the wire never echoes one). */
  hasPassword: boolean
  privateKeyPath: string
  proxyHost: string
  proxyPort: string
  proxyUser: string
  keyboardInteractive: boolean
  color: string
}

const EMPTY_DRAFT: Draft = {
  id: '',
  name: '',
  host: '',
  port: '22',
  username: 'root',
  auth: 'password',
  password: '',
  hasPassword: false,
  privateKeyPath: '',
  proxyHost: '',
  proxyPort: '22',
  proxyUser: '',
  keyboardInteractive: false,
  color: '',
}

function field(label: string, value: string, onChange: (v: string) => void, placeholder?: string, type?: string): ReactElement {
  return createElement('label', { className: 'rdv-field' },
    createElement('span', { className: 'rdv-label' }, label),
    createElement(Input, {
      value,
      type: type ?? 'text',
      placeholder,
      onChange: (e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value),
      autoComplete: 'off',
      spellCheck: false,
    }))
}

/** Preset marker colors offered in the palette (readable as icon colors on light and dark themes). */
const COLOR_PRESETS = ['#3b82f6', '#22c55e', '#ef4444', '#f97316', '#8b5cf6', '#06b6d4', '#ec4899', '#14b8a6']

/**
 * The 远程开发 settings section.
 * @param props - owner conversation plus the injected machine API.
 * @returns the section element.
 */
export function MachinesSection(props: SettingsSectionOwnerProps & SettingsInjected): ReactElement {
  const { t } = props
  const [machines, setMachines] = useState<ClientMachine[]>([])
  const [draft, setDraft] = useState<Draft | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<ClientMachine | null>(null)
  const [deleteError, setDeleteError] = useState('')
  const [paletteOpen, setPaletteOpen] = useState(false)

  // The palette belongs to one draft form; closing the form closes it too.
  useEffect(() => { if (draft === null) setPaletteOpen(false) }, [draft])

  const refresh = useCallback((): void => {
    void props.listMachines().then((r) => {
      setMachines(r.machines)
    }).catch((err: Error) => setError(err.message))
  }, [props])

  useEffect(() => { refresh() }, [refresh])

  const save = (): void => {
    if (!draft) return
    if (!draft.host.trim()) { setError(t('settings.host') + ' ?'); return }
    setBusy(true)
    setError('')
    void props.saveMachine({
      id: draft.id || undefined,
      name: draft.name || draft.host,
      host: draft.host.trim(),
      port: Number(draft.port) || 22,
      username: draft.username.trim(),
      // An untouched stored password travels as absent: the server keeps the
      // stored secret, since the wire never echoes one back.
      password: draft.auth === 'password' ? (draft.password === '' && draft.hasPassword ? undefined : draft.password) : '',
      privateKeyPath: draft.auth === 'key' ? draft.privateKeyPath.trim() : '',
      useAgent: draft.auth === 'agent',
      keyboardInteractive: draft.keyboardInteractive,
      proxyHost: draft.proxyHost.trim(),
      proxyPort: Number(draft.proxyPort) || 22,
      proxyUser: draft.proxyUser.trim(),
      color: draft.color.trim(),
    }).then(() => {
      setDraft(null)
      setBusy(false)
      refresh()
      // A color change re-marks every workspace the machine serves.
      void props.refreshTreeMark()
    }).catch((err: Error) => {
      setError(err.message)
      setBusy(false)
    })
  }

  const test = (machine: Record<string, unknown>): void => {
    setBusy(true)
    setError('')
    setNotice('')
    void props.testConnection(machine).then((r) => {
      setBusy(false)
      if (r.ok) setNotice(`${t('settings.connected')}${r.platform ? ' · ' + t('settings.platform').replace('{platform}', r.platform) : ''}`)
      else setError(r.error ?? t('settings.testFailed'))
    }).catch((err: Error) => {
      setBusy(false)
      setError(err.message)
    })
  }

  const remove = (machine: ClientMachine): void => {
    setBusy(true)
    setDeleteError('')
    void props.deleteMachine(machine.id).then(() => {
      setBusy(false)
      setDeleteTarget(null)
      refresh()
      // The surviving anchors lose their machine join and fall back to the
      // default marker color.
      void props.refreshTreeMark()
    }).catch((err: Error) => {
      setBusy(false)
      setDeleteError(err.message)
    })
  }

  return createElement('div', { className: 'rdv-page' },
    createElement('p', { className: 'rdv-intro' }, t('settings.intro')),
    draft === null && createElement('div', { className: 'rdv-actions', style: { justifyContent: 'flex-start', marginTop: 0 } },
      createElement(Button, {
        variant: 'primary',
        onClick: () => { setDraft({ ...EMPTY_DRAFT }); setError(''); setNotice('') },
      }, t('settings.add')),
    ),
    error && createElement('div', { className: 'rdv-error' }, error),
    notice && createElement('div', { className: 'rdv-ok' }, notice),
    createElement('div', { className: 'rdv-cards' },
      machines.length === 0 && draft === null
        ? createElement('div', { className: 'rdv-empty' }, t('settings.noMachines'))
        : machines.map((m) => createElement('div', { key: m.id, className: 'rdv-card' },
            createElement('div', { className: 'rdv-cardMain' },
              createElement('div', { className: 'rdv-cardName' },
                m.color !== '' && createElement('span', {
                  'aria-hidden': true,
                  style: { width: 10, height: 10, borderRadius: 5, background: m.color, flex: 'none' },
                }),
                createElement('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, m.name),
              ),
              createElement('div', { className: 'rdv-cardHost' }, `${m.username}@${m.host}:${m.port}`),
            ),
            createElement('div', { className: 'rdv-cardActions' },
              createElement(Button, { size: 'sm', disabled: busy, onClick: () => test({ machineId: m.id }) }, t('settings.test')),
              createElement(Button, {
                size: 'sm',
                disabled: busy,
                onClick: () => setDraft({
                  id: m.id,
                  name: m.name,
                  host: m.host,
                  port: String(m.port),
                  username: m.username,
                  auth: m.hasPassword ? 'password' : (m.privateKeyPath ? 'key' : 'agent'),
                  password: '',
                  hasPassword: m.hasPassword,
                  privateKeyPath: m.privateKeyPath,
                  proxyHost: m.proxyHost,
                  proxyPort: '22',
                  proxyUser: '',
                  keyboardInteractive: m.keyboardInteractive,
                  color: m.color,
                }),
              }, t('settings.edit')),
              createElement(Button, {
                size: 'sm',
                disabled: busy,
                onClick: () => { setDeleteTarget(m); setDeleteError('') },
              }, t('settings.delete')),
            ),
          )),
    ),
    draft !== null && createElement('div', { className: 'rdv-form' },
      createElement('div', { className: 'rdv-row' },
        field(t('settings.name'), draft.name, (v) => setDraft({ ...draft, name: v }), draft.host || 'my-server'),
        field(t('settings.host'), draft.host, (v) => setDraft({ ...draft, host: v }), '203.0.113.10'),
        field(t('settings.port'), draft.port, (v) => setDraft({ ...draft, port: v }), '22'),
        field(t('settings.username'), draft.username, (v) => setDraft({ ...draft, username: v }), 'root'),
      ),
      createElement('div', { className: 'rdv-row' },
        createElement('label', { className: 'rdv-field' },
          createElement('span', { className: 'rdv-label' }, t('settings.auth')),
          createElement('select', {
            className: 'rdv-select',
            value: draft.auth,
            onChange: (e: React.ChangeEvent<HTMLSelectElement>) => setDraft({ ...draft, auth: e.target.value as Draft['auth'] }),
          },
            createElement('option', { value: 'password' }, t('settings.authPassword')),
            createElement('option', { value: 'key' }, t('settings.authKey')),
            createElement('option', { value: 'agent' }, t('settings.authAgent')),
          ),
        ),
        draft.auth === 'password' && field(
          t('settings.password'),
          draft.password,
          (v) => setDraft({ ...draft, password: v }),
          draft.id && draft.hasPassword && !draft.password ? t('settings.passwordKeep') : '',
          'password',
        ),
        draft.auth === 'key' && field(
          t('settings.privateKeyPath'),
          draft.privateKeyPath,
          (v) => setDraft({ ...draft, privateKeyPath: v }),
          '~/.ssh/id_ed25519',
        ),
      ),
      createElement('div', { className: 'rdv-row' },
        createElement('div', { className: 'rdv-field', style: { position: 'relative' } },
          createElement('span', { className: 'rdv-label' }, t('settings.color')),
          createElement('button', {
            type: 'button',
            className: 'rdv-colorTrigger',
            onClick: () => setPaletteOpen(!paletteOpen),
          },
            draft.color !== '' && createElement('span', { className: 'rdv-colorDot', style: { background: draft.color } }),
            createElement('span', null, draft.color === '' ? t('settings.colorDefault') : draft.color),
          ),
          paletteOpen && draft !== null && createElement(Fragment, null,
            createElement('div', { className: 'rdv-paletteBackdrop', onClick: () => setPaletteOpen(false) }),
            createElement('div', { className: 'rdv-palette', role: 'listbox', 'aria-label': t('settings.color') },
              createElement('button', {
                type: 'button',
                role: 'option',
                'aria-selected': draft.color === '',
                className: 'rdv-swatch rdv-swatchDefault' + (draft.color === '' ? ' rdv-swatchActive' : ''),
                title: t('settings.colorDefault'),
                onClick: () => { setDraft({ ...draft, color: '' }); setPaletteOpen(false) },
              }),
              COLOR_PRESETS.map((c) => createElement('button', {
                key: c,
                type: 'button',
                role: 'option',
                'aria-selected': draft.color.toLowerCase() === c,
                className: 'rdv-swatch' + (draft.color.toLowerCase() === c ? ' rdv-swatchActive' : ''),
                style: { background: c },
                title: c,
                onClick: () => { setDraft({ ...draft, color: c }); setPaletteOpen(false) },
              })),
            ),
          ),
        ),
      ),
      createElement('details', { className: 'rdv-field' },
        createElement('summary', { className: 'rdv-label', style: { cursor: 'pointer' } }, t('settings.advanced')),
        createElement('div', { className: 'rdv-row', style: { marginTop: 8 } },
          field(t('settings.proxyHost'), draft.proxyHost, (v) => setDraft({ ...draft, proxyHost: v }), ''),
          field(t('settings.proxyPort'), draft.proxyPort, (v) => setDraft({ ...draft, proxyPort: v }), '22'),
          field(t('settings.proxyUser'), draft.proxyUser, (v) => setDraft({ ...draft, proxyUser: v }), ''),
        ),
        createElement('label', { className: 'rdv-label', style: { display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 } },
          createElement('input', {
            type: 'checkbox',
            checked: draft.keyboardInteractive,
            onChange: (e: React.ChangeEvent<HTMLInputElement>) => setDraft({ ...draft, keyboardInteractive: e.target.checked }),
          }),
          t('settings.keyboardInteractive'),
        ),
      ),
      createElement('div', { className: 'rdv-actions' },
        createElement(Button, { disabled: busy, onClick: () => setDraft(null) }, t('settings.cancel')),
        createElement(Button, { variant: 'primary', disabled: busy, onClick: save }, t('settings.save')),
      ),
    ),
    createElement(Modal, {
      open: deleteTarget !== null,
      onClose: () => { if (!busy) setDeleteTarget(null) },
      title: t('settings.deleteTitle'),
      closeLabel: t('settings.cancel'),
      description: deleteTarget === null
        ? ''
        : t('settings.deleteConfirm').replace('{name}', `${deleteTarget.name} (${deleteTarget.username}@${deleteTarget.host}:${deleteTarget.port})`),
      footer: createElement(Fragment, null,
        createElement(Button, { variant: 'outline', autoFocus: true, disabled: busy, onClick: () => setDeleteTarget(null) }, t('settings.cancel')),
        createElement(Button, {
          variant: 'outline',
          disabled: busy || deleteTarget === null,
          onClick: () => { if (deleteTarget !== null) remove(deleteTarget) },
        }, t('settings.confirmDelete')),
      ),
    }, deleteError === '' ? null : createElement('p', { className: 'rdv-error', style: { margin: 0 } }, deleteError)),
  )
}
