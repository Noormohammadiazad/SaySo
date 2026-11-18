// Drawers, dialogs and the appearance controls. Modal by the book: focus
// moves in and stays in, Esc and the backdrop close them, the close button
// is labelled, and focus returns where it was. Not needed for the first
// screen, so the sender's view loads this module after it.
import type { ComponentChildren } from 'preact'
import { useLayoutEffect, useRef } from 'preact/hooks'
import { IconButton } from './kit'
import { prefs, t, type Locale, type Theme } from './prefs'
import './overlays.css'
import './strings-more'

/** Close on Esc, keep focus inside, give it back on close. */
function useModal(open: boolean, onClose: () => void) {
  const panel = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => {
    if (!open) return
    const before = document.activeElement as HTMLElement | null
    const focusable = (): HTMLElement[] =>
      [...(panel.current?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? [])].filter(
        (el) => !el.hasAttribute('disabled'),
      )
    ;(focusable().find((el) => !el.classList.contains('icon-button')) ?? focusable()[0] ?? panel.current)?.focus()
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        onClose()
      } else if (event.key === 'Tab') {
        const items = focusable()
        if (!items.length) return
        const first = items[0]
        const last = items[items.length - 1]
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault()
          last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey, true)
    document.body.classList.add('modal-open')
    return () => {
      document.removeEventListener('keydown', onKey, true)
      document.body.classList.remove('modal-open')
      before?.focus?.()
    }
  }, [open])
  return panel
}

/** A panel that slides in from the end side (right in English, left in Persian). */
export function Drawer({ open, title, onClose, children }: { open: boolean; title: string; onClose: () => void; children: ComponentChildren }) {
  const panel = useModal(open, onClose)
  if (!open) return null
  return (
    <div class="overlay" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <div class="drawer" role="dialog" aria-modal="true" aria-label={title} ref={panel} tabIndex={-1}>
        <header class="drawer-head">
          <h2>{title}</h2>
          <IconButton icon="close" label={t('action.close')} onClick={onClose} />
        </header>
        <div class="drawer-body">{children}</div>
      </div>
    </div>
  )
}

export function Dialog({
  open,
  title,
  onClose,
  children,
  actions,
}: {
  open: boolean
  title: string
  onClose: () => void
  children?: ComponentChildren
  actions: ComponentChildren
}) {
  const panel = useModal(open, onClose)
  if (!open) return null
  return (
    <div class="overlay center" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <div class="dialog" role="dialog" aria-modal="true" aria-label={title} ref={panel} tabIndex={-1}>
        <h2>{title}</h2>
        {children}
        <div class="dialog-actions">{actions}</div>
      </div>
    </div>
  )
}

/** Ask before something that cannot be undone. */
export function Confirm({ open, title, body, action, onConfirm, onClose }: {
  open: boolean
  title: string
  body?: string
  action: string
  onConfirm: () => void
  onClose: () => void
}) {
  return (
    <Dialog
      open={open}
      title={title}
      onClose={onClose}
      actions={
        <>
          <button type="button" class="ghost" onClick={onClose}>
            {t('action.cancel')}
          </button>
          <button
            type="button"
            class="danger"
            onClick={() => {
              onClose()
              onConfirm()
            }}
          >
            {action}
          </button>
        </>
      }
    >
      {body && <p class="muted">{body}</p>}
    </Dialog>
  )
}

/** A row of mutually exclusive choices. */
export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T
  options: { value: T; label: string }[]
  onChange: (value: T) => void
  label: string
}) {
  return (
    <div class="segmented" role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <button type="button" role="radio" aria-checked={option.value === value} key={option.value} onClick={() => onChange(option.value)}>
          {option.label}
        </button>
      ))}
    </div>
  )
}

/** Language and theme, as every settings drawer shows them. */
export function AppearanceSettings() {
  return (
    <section class="group">
      <h3>{t('appearance')}</h3>
      <div class="field">
        <span class="label">{t('language')}</span>
        <Segmented<Locale>
          label={t('language')}
          value={prefs.locale}
          onChange={(locale) => prefs.setLocale(locale)}
          options={[
            { value: 'fa', label: 'فارسی' },
            { value: 'en', label: 'English' },
          ]}
        />
      </div>
      <div class="field">
        <span class="label">{t('theme')}</span>
        <Segmented<Theme>
          label={t('theme')}
          value={prefs.theme}
          onChange={(theme) => prefs.setTheme(theme)}
          options={[
            { value: 'system', label: t('theme.system') },
            { value: 'light', label: t('theme.light') },
            { value: 'dark', label: t('theme.dark') },
          ]}
        />
      </div>
    </section>
  )
}

