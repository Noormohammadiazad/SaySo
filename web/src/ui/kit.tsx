// The few building blocks every screen is made of. Accessible by default:
// menus open on click or keyboard and close on Esc or outside click, and
// every icon-only button has a label. Drawers and dialogs are in
// ./overlays, which loads after the first screen.
import type { ComponentChildren, JSX } from 'preact'
import { useEffect, useRef, useState } from 'preact/hooks'

const PATHS = {
  send: 'M4 12 20 4l-6 16-3-7-7-1Z',
  attach: 'm21 11-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7',
  close: 'M6 6l12 12M18 6 6 18',
  more: 'M5 12h.01M12 12h.01M19 12h.01',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z',
  back: 'M15 6l-6 6 6 6',
  check: 'm5 12 5 5L20 7',
  checks: 'm2 12 5 5L17 7m-3 10 8-10',
  clock: 'M12 7v5l3 2M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z',
  alert: 'M12 8v5m0 3h.01M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z',
  shield: 'M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6l-8-3Zm-3 9 2 2 4-4',
  trash: 'M4 7h16M10 11v6m4-6v6M6 7l1 13h10l1-13M9 7V4h6v3',
  edit: 'M4 20h4L19 9l-4-4L4 16v4Zm9-13 4 4',
  block: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM5.6 5.6l12.8 12.8',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
  file: 'M14 3H6v18h12V7l-4-4Zm0 0v4h4',
  download: 'M12 4v11m-5-5 5 5 5-5M5 20h14',
  lock: 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4',
  link: 'M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1m2 4a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1',
} as const

export type IconName = keyof typeof PATHS

export function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  return (
    <svg class={`icon icon-${name}`} width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <path d={PATHS[name]} />
    </svg>
  )
}

type ButtonProps = JSX.HTMLAttributes<HTMLButtonElement> & { disabled?: boolean; type?: 'button' | 'submit' }

export function IconButton({ icon, label, ...rest }: ButtonProps & { icon: IconName; label: string }) {
  return (
    <button type="button" class="icon-button" aria-label={label} title={label} {...rest}>
      <Icon name={icon} />
    </button>
  )
}

export type Tone = 'ok' | 'busy' | 'warn' | 'off'

export function Pill({ tone, children, title }: { tone: Tone; children: ComponentChildren; title?: string }) {
  return (
    <span class={`pill ${tone}`} title={title}>
      <span class="dot" aria-hidden="true" />
      {children}
    </span>
  )
}

/** Initials on a colour picked from the id, the same everywhere. */
export function Avatar({ name, id, size = 40 }: { name: string; id: string; size?: number }) {
  const hue = parseInt(id.slice(0, 4), 16) % 360 || 220
  const letter = [...(name.trim() || '?')][0].toUpperCase()
  return (
    <span class="avatar" aria-hidden="true" style={{ '--hue': hue, width: `${size}px`, height: `${size}px`, fontSize: `${size * 0.42}px` }}>
      {letter}
    </span>
  )
}

export interface MenuItem {
  label: string
  icon: IconName
  onSelect: () => void
  danger?: boolean
  hidden?: boolean
}

/** A ⋯ button that opens a short list of actions. */
export function Menu({ label, items, align = 'end' }: { label: string; items: MenuItem[]; align?: 'start' | 'end' }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const shown = items.filter((item) => !item.hidden)
  useEffect(() => {
    if (!open) return
    const outside = (event: Event): void => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    const key = (event: KeyboardEvent): void => {
      const buttons = [...(root.current?.querySelectorAll<HTMLButtonElement>('[role=menuitem]') ?? [])]
      const at = buttons.indexOf(document.activeElement as HTMLButtonElement)
      if (event.key === 'Escape') {
        setOpen(false)
        root.current?.querySelector<HTMLButtonElement>('.icon-button')?.focus()
      } else if (event.key === 'ArrowDown') {
        event.preventDefault()
        buttons[(at + 1) % buttons.length]?.focus()
      } else if (event.key === 'ArrowUp') {
        event.preventDefault()
        buttons[(at - 1 + buttons.length) % buttons.length]?.focus()
      }
    }
    document.addEventListener('pointerdown', outside)
    document.addEventListener('keydown', key)
    root.current?.querySelector<HTMLButtonElement>('[role=menuitem]')?.focus()
    return () => {
      document.removeEventListener('pointerdown', outside)
      document.removeEventListener('keydown', key)
    }
  }, [open])
  if (!shown.length) return null
  return (
    <div class="menu" ref={root}>
      <IconButton icon="more" label={label} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)} />
      {open && (
        <div class={`menu-list ${align}`} role="menu">
          {shown.map((item) => (
            <button
              type="button"
              role="menuitem"
              key={item.label}
              class={item.danger ? 'danger-text' : ''}
              onClick={() => {
                setOpen(false)
                item.onSelect()
              }}
            >
              <Icon name={item.icon} size={18} />
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

/** A short notice in the flow of the page. */
export function Banner({ tone = 'info', children }: { tone?: 'info' | 'warn'; children: ComponentChildren }) {
  return (
    <div class={`banner ${tone}`} role={tone === 'warn' ? 'alert' : 'status'}>
      <Icon name={tone === 'warn' ? 'alert' : 'lock'} size={18} />
      <div>{children}</div>
    </div>
  )
}
