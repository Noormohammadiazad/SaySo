// The sender view's drawer and confirmations: loaded after the first
// screen (or when first opened), so they cost the first visit nothing.
import { Icon } from '../ui/kit'
import { AppearanceSettings, Confirm, Drawer } from '../ui/overlays'
import { t } from '../ui/prefs'
import type { SenderSession } from './session'

export type Ask = { kind: 'message'; id: string } | { kind: 'conversation' }

export function SenderOverlays({
  session,
  settings,
  closeSettings,
  ask,
  closeAsk,
  run,
  notify,
}: {
  session: SenderSession
  settings: boolean
  closeSettings: () => void
  ask?: Ask
  closeAsk: () => void
  run: (action: () => Promise<void>) => void
  notify: (text: string) => void
}) {
  const link = session.resumeLink()
  return (
    <>
      <Drawer open={settings} title={t('settings')} onClose={closeSettings}>
        <AppearanceSettings />
        <section class="group">
          <h3>{t('conversation')}</h3>
          <p class="muted">
            {session.identity === 'none' ? t('identity.none') : session.identity === 'device' ? t('identity.device') : t('identity.passkey')}
          </p>
          {link && (
            <button
              type="button"
              class="ghost"
              onClick={() =>
                run(async () => {
                  await navigator.clipboard.writeText(link)
                  notify(t('identity.copied'))
                })
              }
            >
              <Icon name="link" size={18} />
              {t('identity.copyLink')}
            </button>
          )}
          {session.identity === 'none' && session.passkeys && (
            <button type="button" class="ghost" onClick={() => run(() => session.usePasskey())}>
              <Icon name="lock" size={18} />
              {t('identity.usePasskey')}
            </button>
          )}
        </section>
        {session.messages.length > 0 && (
          <section class="group danger-zone">
            <p class="muted">{t('conversation.deleteHint')}</p>
            <button
              type="button"
              class="danger"
              onClick={() => {
                closeSettings()
                // The confirmation opens over the page, not over the closing drawer.
                setTimeout(() => run(async () => void askConversation()), 0)
              }}
            >
              <Icon name="trash" size={18} />
              {t('conversation.delete')}
            </button>
          </section>
        )}
      </Drawer>

      <Confirm
        open={!!ask}
        title={ask?.kind === 'conversation' ? t('confirm.deleteConversation') : t('confirm.deleteMessage')}
        body={t('confirm.cannotUndo')}
        action={t('action.delete')}
        onClose={closeAsk}
        onConfirm={() => {
          if (ask?.kind === 'conversation') run(() => session.deleteConversation())
          else if (ask) run(() => session.deleteMessage(ask.id))
        }}
      />
    </>
  )

  function askConversation(): void {
    window.dispatchEvent(new CustomEvent('sayso:ask-conversation'))
  }
}
