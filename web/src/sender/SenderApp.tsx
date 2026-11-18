import { useEffect, useMemo, useRef, useState } from 'preact/hooks'
import { Bubble, type Status } from '../ui/Bubble'
import { Composer } from '../ui/Composer'
import { errorText } from '../ui/format'
import { Avatar, Banner, Icon, IconButton, Pill, type Tone } from '../ui/kit'
import { prefs, t } from '../ui/prefs'
import { Connecting, Failed, Screen } from '../ui/Screens'
import { useObservable } from '../ui/store'
import '../ui/strings'
import type { Ask } from './SenderOverlays'
import { SenderSession, type ChatMessage } from './session'

type Overlays = typeof import('./SenderOverlays')
const loadOverlays = (): Promise<Overlays> => import('./SenderOverlays')

const percent = (fraction: number): number => Math.floor(fraction * 100)

function statusOf(message: ChatMessage): Status | undefined {
  if (message.dir === 'in') {
    return message.progress !== undefined ? { icon: 'download', label: t('status.downloading', { percent: percent(message.progress) }) } : undefined
  }
  switch (message.state) {
    case 'queued':
      return { icon: 'clock', label: t('status.queued') }
    case 'sending':
      return { icon: 'clock', label: t('status.sending') }
    case 'uploading':
      return { icon: 'clock', label: t('status.uploading', { percent: percent(message.progress ?? 0) }) }
    case 'buffered':
      return { icon: 'check', label: t('status.sent') }
    case 'delivered':
      return { icon: 'checks', label: t('status.delivered'), tone: 'ok' }
    case 'failed':
      return { icon: 'alert', label: t('status.failed'), tone: 'warn' }
  }
}

const REPLIES: Record<string, [Tone, string]> = {
  live: ['ok', 'sender.live'],
  connecting: ['busy', 'sender.connecting'],
  retrying: ['warn', 'sender.offline'],
}

export function SenderApp() {
  const session = useObservable(useMemo(() => new SenderSession(), []))
  useObservable(prefs)
  const [notice, setNotice] = useState<string>()
  const [settings, setSettings] = useState(false)
  const [confirm, setConfirm] = useState<Ask>()
  const [overlays, setOverlays] = useState<Overlays>()
  const end = useRef<HTMLDivElement>(null)

  // The drawer and dialogs come after the first screen, quietly.
  useEffect(() => {
    const load = (): void => void loadOverlays().then(setOverlays, () => undefined)
    const idle = (window as { requestIdleCallback?: (fn: () => void) => number }).requestIdleCallback
    if (idle) idle(load)
    else setTimeout(load, 1500)
    const ask = (): void => setConfirm({ kind: 'conversation' })
    window.addEventListener('sayso:ask-conversation', ask)
    return () => window.removeEventListener('sayso:ask-conversation', ask)
  }, [])
  const open = (show: () => void) => () => {
    if (!overlays) void loadOverlays().then(setOverlays)
    show()
  }

  useEffect(() => void session.start(), [session])
  useEffect(() => end.current?.scrollIntoView({ block: 'end' }), [session.messages.length])

  const guard = (action: () => Promise<void>) => () => {
    setNotice(undefined)
    action().catch((err) => setNotice(errorText(err)))
  }

  // Verifying the owner's document takes milliseconds; nothing to show yet.
  if (session.phase === 'starting') return <main class="screen" />
  if (session.phase === 'connecting') return <Connecting title="Sayso" what={t('connecting.inbox')} status={session.status} />
  if (session.phase === 'error') return <Failed failure={session.failure} />
  if (session.phase === 'unconfigured') {
    return (
      <Screen title={t('unconfigured.title')}>
        <p>{t('unconfigured.body')}</p>
      </Screen>
    )
  }
  if (session.phase === 'no-inbox') {
    return (
      <Screen title={t('noInbox.title')}>
        <p>{t('noInbox.body')}</p>
        <a class="button" href="#/owner">
          {t('noInbox.link')}
        </a>
      </Screen>
    )
  }
  if (session.phase === 'key-changed') {
    return (
      <Screen title={t('keyChanged.title')}>
        <p>{t('keyChanged.body')}</p>
      </Screen>
    )
  }
  if (session.phase === 'locked') {
    return (
      <Screen title={t('locked.title', { name: session.name })}>
        <p>{t('locked.body')}</p>
        <button type="button" onClick={guard(() => session.usePasskey())}>
          {t('locked.button')}
        </button>
        {notice && <p class="error">{notice}</p>}
      </Screen>
    )
  }

  const replies = REPLIES[session.replies]
  const live =
    session.link === 'idle'
      ? undefined
      : session.link === 'loading'
        ? (['busy', session.liveProgress === undefined ? t('link.loading') : t('link.loadingPercent', { percent: percent(session.liveProgress) })] as const)
        : session.link === 'live'
          ? (['ok', t('link.live')] as const)
          : session.link === 'connecting'
            ? (['busy', t('link.connecting')] as const)
            : (['off', t('link.offline')] as const)
  const waiting = session.messages.some((m) => m.dir === 'out' && m.files?.length && m.state === 'queued')

  return (
    <div class="app chat">
      <header class="bar">
        <Avatar name={session.name} id={session.fingerprint.replace(/\s/g, '')} />
        <div class="bar-title">
          <h1 dir="auto">{session.name}</h1>
          {session.github ? (
            <p class="sub">
              <span class="badge ok" title={t('sender.verifiedGithubHint', { repo: session.github.repo })}>
                <Icon name="shield" size={14} />
                {t('sender.verifiedGithub')}
              </span>
              <a href={`https://github.com/${session.github.login}`} target="_blank" rel="noreferrer" dir="ltr">
                @{session.github.login}
              </a>
            </p>
          ) : (
            <p class="sub muted">{t('sender.unanchored')}</p>
          )}
        </div>
        <div class="bar-status">
          {replies && <Pill tone={replies[0]}>{t(replies[1])}</Pill>}
          {live && <Pill tone={live[0]}>{live[1]}</Pill>}
        </div>
        <IconButton icon="settings" label={t('settings')} onClick={open(() => setSettings(true))} />
      </header>

      <div class="scroll">
        <p class="keyline muted">
          <Icon name="lock" size={14} />
          <span>{t('sender.key', { fp: '' })}</span>
          <code dir="ltr">{session.fingerprint}</code>
        </p>
        {session.verifiedAs && (
          <Banner>
            {t('sender.verifiedAs', { owner: session.name, label: session.verifiedAs })}
          </Banner>
        )}
        {session.invited && !session.verifiedAs && <Banner>{t('sender.invited')}</Banner>}
        {session.relays === 0 && session.link === 'offline' && <Banner>{t('sender.noRelay')}</Banner>}
        {waiting && session.link !== 'live' && <Banner>{t('sender.filesWaiting')}</Banner>}

        <ul class="thread" aria-live="polite">
          {session.messages.length === 0 && <li class="empty">{t('sender.empty')}</li>}
          {session.messages.map((message) => (
            <Bubble
              key={message.id}
              mine={message.dir === 'out'}
              ts={message.ts}
              text={message.text}
              files={message.files}
              status={statusOf(message)}
              note={message.state === 'failed' || message.state === 'queued' ? message.note : undefined}
              fileAction={(file) =>
                message.dir === 'in' && (
                  <IconButton icon="download" label={t('message.download')} onClick={guard(() => session.download(message, file))} />
                )
              }
              actions={[
                { label: t('action.copy'), icon: 'copy', hidden: !message.text, onSelect: () => void navigator.clipboard?.writeText(message.text ?? '') },
                { label: t('message.deleteBoth'), icon: 'trash', danger: true, onSelect: open(() => setConfirm({ kind: 'message', id: message.id })) },
              ]}
            />
          ))}
          <div ref={end} />
        </ul>
      </div>

      <Composer placeholder={t('composer.placeholder')} busy={session.busy} onSend={(text, files, options) => session.send(text, files, options)} />
      {notice && (
        <p class="error inline" role="alert">
          {notice}
        </p>
      )}

      {overlays && (
        <overlays.SenderOverlays
          session={session}
          settings={settings}
          closeSettings={() => setSettings(false)}
          ask={confirm}
          closeAsk={() => setConfirm(undefined)}
          run={(action) => guard(action)()}
          notify={setNotice}
        />
      )}
    </div>
  )
}
