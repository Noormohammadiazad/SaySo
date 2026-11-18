import type { ComponentChildren } from 'preact'
import { Icon } from './kit'
import { t } from './prefs'

/** A centred card with a title: every not-yet-running state. */
export function Screen({ title, children, wide }: { title: string; children?: ComponentChildren; wide?: boolean }) {
  return (
    <main class={`screen ${wide ? 'wide' : ''}`}>
      <div class="card">
        <div class="brand" aria-hidden="true">
          <Icon name="lock" size={18} /> Sayso
        </div>
        <h1>{title}</h1>
        {children}
      </div>
    </main>
  )
}

/** Waiting for the network, which is being retried on its own. */
export function Connecting({ title, what, status }: { title: string; what: string; status?: string }) {
  return (
    <Screen title={title}>
      <p>{what}</p>
      <div class="progress indeterminate" aria-hidden="true">
        <span />
      </div>
      {status && (
        <p class="muted" aria-live="polite">
          {status}
        </p>
      )}
    </Screen>
  )
}

/** Starting failed in a way that retrying on its own will not fix. */
export function Failed({ failure }: { failure?: { step: string; reason: string } }) {
  return (
    <Screen title={t('error.title')}>
      <p>
        <strong>{t('error.failed', { step: failure?.step ?? 'Starting' })}</strong> <span dir="auto">{failure?.reason}</span>
      </p>
      <p class="muted">{t('error.note')}</p>
      <button type="button" onClick={() => location.reload()}>
        {t('action.retry')}
      </button>
    </Screen>
  )
}
