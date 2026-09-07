/**
 * The plugin's stylesheet, injected once per page load. Class names carry the
 * `rdv-` prefix and every color/spacing value reads the harness `--dsw-*`
 * tokens, so light/dark themes follow the shell without extra work.
 * @module dsh-remote-development/client/styles
 */

const CSS = `
.rdv-page { display: flex; flex-direction: column; gap: 16px; max-width: 720px; }
.rdv-intro { margin: 0; color: var(--dsw-alias-label-secondary); font-size: 13px; line-height: 20px; }
.rdv-cards { display: flex; flex-direction: column; gap: 8px; }
.rdv-card { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border: 1px solid var(--dsw-alias-border-l3); border-radius: 10px; background: var(--dsw-alias-bg-layer-1); }
.rdv-cardMain { display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1; }
.rdv-cardName { color: var(--dsw-alias-label-primary); font-size: 14px; font-weight: 510; line-height: 20px; display: flex; align-items: center; gap: 8px; }
.rdv-cardHost { color: var(--dsw-alias-label-secondary); font-size: 12px; line-height: 18px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rdv-cardActions { display: flex; align-items: center; gap: 4px; flex: none; }
.rdv-form { display: flex; flex-direction: column; gap: 12px; padding: 16px; border: 1px solid var(--dsw-alias-border-l2); border-radius: 12px; background: var(--dsw-alias-bg-layer-2); }
.rdv-row { display: flex; gap: 10px; }
.rdv-row > * { flex: 1; min-width: 0; }
.rdv-field { display: flex; flex-direction: column; gap: 5px; }
.rdv-label { color: var(--dsw-alias-label-secondary); font-size: 12px; font-weight: 500; line-height: 18px; }
.rdv-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px; }
.rdv-error { color: var(--dsw-alias-state-error-primary); font-size: 12px; line-height: 18px; white-space: pre-wrap; }
.rdv-ok { color: var(--dsw-alias-state-success-primary, var(--dsw-alias-label-primary)); font-size: 12px; line-height: 18px; }
.rdv-dialog { position: fixed; inset: 0; z-index: 60; display: flex; align-items: center; justify-content: center; background: var(--dsw-alias-overlay-bg, rgba(0,0,0,0.4)); }
.rdv-sheet { display: flex; flex-direction: column; width: min(640px, calc(100vw - 32px)); height: min(520px, calc(100dvh - 48px)); background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l3); border-radius: 14px; box-shadow: 0 18px 48px rgba(0,0,0,0.25); overflow: hidden; }
.rdv-sheetHead { display: flex; align-items: center; gap: 12px; padding: 14px 18px 10px; border-bottom: 1px solid var(--dsw-alias-border-l3); }
.rdv-tabs { display: flex; gap: 2px; padding: 3px; border-radius: 9px; background: var(--dsw-alias-bg-layer-2); }
.rdv-tab { border: none; background: transparent; border-radius: 7px; padding: 5px 14px; color: var(--dsw-alias-label-secondary); font-size: 13px; font-weight: 500; cursor: pointer; }
.rdv-tabActive { background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); box-shadow: 0 1px 2px rgba(0,0,0,0.12); }
.rdv-sheetTitle { color: var(--dsw-alias-label-primary); font-size: 15px; font-weight: 510; flex: 1; }
.rdv-sheetBody { display: flex; flex-direction: column; gap: 10px; padding: 14px 18px; flex: 1; min-height: 0; overflow-y: auto; }
.rdv-hint { margin: 0; color: var(--dsw-alias-label-tertiary); font-size: 12px; line-height: 18px; }
.rdv-toolbar { display: flex; align-items: center; gap: 6px; }
.rdv-pathInput { flex: 1; min-width: 0; height: 30px; border: 1px solid var(--dsw-alias-border-l3); border-radius: 8px; background: transparent; color: var(--dsw-alias-label-primary); padding: 0 10px; font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; outline: none; }
.rdv-pathInput:focus { border-color: var(--dsw-alias-border-l2); }
.rdv-list { display: flex; flex-direction: column; gap: 1px; flex: 1; min-height: 0; overflow-y: auto; border: 1px solid var(--dsw-alias-border-l4); border-radius: 10px; }
.rdv-itemRow { display: flex; align-items: center; gap: 8px; width: 100%; border: none; background: transparent; text-align: left; padding: 8px 12px; color: var(--dsw-alias-label-primary); font-size: 13px; cursor: pointer; }
.rdv-itemRow:hover { background: var(--dsw-alias-interactive-bg-hover); }
.rdv-itemName { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rdv-itemIcon { color: var(--dsw-alias-label-tertiary); flex: none; display: inline-flex; }
.rdv-empty { padding: 24px; text-align: center; color: var(--dsw-alias-label-tertiary); font-size: 13px; }
.rdv-sheetFoot { display: flex; align-items: center; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--dsw-alias-border-l3); }
.rdv-spacer { flex: 1; }
.rdv-status { color: var(--dsw-alias-label-tertiary); font-size: 12px; }
.rdv-select { height: 32px; border: 1px solid var(--dsw-alias-border-l3); border-radius: 8px; background: transparent; color: var(--dsw-alias-label-primary); padding: 0 8px; font-size: 13px; outline: none; min-width: 0; flex: 1; }
/* The native popup does not inherit the page theme: without an explicit
   color-scheme it renders light even under dark tokens, leaving inherited
   near-white option text on a white list. Opaque option colors fix the list
   in every engine; color-scheme under the shell's dark-theme attribute also
   fixes the popup chrome (border, highlight, arrow). */
.rdv-select option { background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); }
body[data-ds-dark-theme] .rdv-select { color-scheme: dark; }
`

/** Inject the stylesheet once (idempotent across plugin reloads). */
export function injectStyles(): () => void {
  if (typeof document === 'undefined') return () => {}
  const existing = document.querySelector('style[data-plugin-css="dsh-remote-development"]')
  if (existing) return () => {}
  const tag = document.createElement('style')
  tag.dataset.pluginCss = 'dsh-remote-development'
  tag.textContent = CSS
  document.head.appendChild(tag)
  return () => tag.remove()
}
