import { useEffect, useMemo, useRef, useState } from 'preact/hooks'
import { toHex } from '../core'
import { suggestPassphrase } from '../identity/keyvault'
import { Bubble, type Status } from '../ui/Bubble'
import { Composer } from '../ui/Composer'
import { errorText } from '../ui/format'
import { Avatar, Banner, Icon, IconButton, Menu, Pill, type Tone } from '../ui/kit'
import { AppearanceSettings, Confirm, Dialog, Drawer } from '../ui/overlays'
import { formatDuration, formatTime, prefs, t } from '../ui/prefs'
import { Connecting, Failed, Screen } from '../ui/Screens'
import { useObservable } from '../ui/store'
import '../ui/strings'
import { Dashboard, type OwnerMessage, type Thread } from './dashboard'
import './owner.css'
import './strings'

export function OwnerApp() {
  const dash = useObservable(useMemo(() => new Dashboard(), []))
  useObservable(prefs)
  useEffect(() => void dash.start(), [dash])

  if (dash.phase === 'connecting') return <Connecting title={t('owner.title')} what={t('owner.reading')} status={dash.status} />
  if (dash.phase === 'error') return <Failed failure={dash.failure} />
  if (dash.phase === 'unconfigured') {
    return (
      <Screen title={t('unconfigured.title')}>
        <p>{t('unconfigured.body')}</p>
      </Screen>
    )
  }
  if (dash.phase === 'signin' || dash.phase === 'setup') return <SignIn dash={dash} />
  return <Running dash={dash} />
}

/** Signing in and creating the inbox: one form, both start from a token and a passphrase. */
function SignIn({ dash }: { dash: Dashboard }) {
  const creating = dash.phase === 'setup'
  const [token, setToken] = useState(dash.checkedToken ?? '')
  const [name, setName] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [remember, setRemember] = useState(true)
  const [reveal, setReveal] = useState(false)
  const busy = !!dash.busy
  const submit = (event: Event) => {
    event.preventDefault()
    void (creating ? dash.create(name, token, passphrase, confirm, remember) : dash.signIn(token, passphrase, remember))
  }
  const suggest = () => {
    const fresh = suggestPassphrase()
    setPassphrase(fresh)
    setConfirm(fresh)
    setReveal(true)
  }
  return (
    <Screen title={creating ? t('setup.title') : t('signin.title')}>
      <p class="muted">{t(creating ? 'setup.lead' : 'signin.lead', { repo: dash.repoName })}</p>
      {dash.formNote && <Banner>{dash.formNote}</Banner>}
      <form class="form" onSubmit={submit}>
        {creating && (
          <label>
            {t('form.name')}
            <input value={name} dir="auto" autocomplete="name" onInput={(event) => setName(event.currentTarget.value)} placeholder={t('form.namePlaceholder')} />
          </label>
        )}
        {!dash.local && (
          <label>
            {t('form.token')}
            <input
              type="password"
              value={token}
              dir="ltr"
              autocomplete="off"
              spellcheck={false}
              onInput={(event) => setToken(event.currentTarget.value)}
              placeholder="github_pat_…"
            />
            <span class="hint muted">{t('form.tokenHint', { repo: dash.repoName })}</span>
          </label>
        )}
        <label>
          {creating ? t('form.newPassphrase') : t('form.passphrase')}
          <input
            type={reveal ? 'text' : 'password'}
            value={passphrase}
            dir="auto"
            autocomplete={creating ? 'new-password' : 'current-password'}
            onInput={(event) => setPassphrase(event.currentTarget.value)}
          />
        </label>
        {creating && (
          <>
            <label>
              {t('form.repeat')}
              <input type={reveal ? 'text' : 'password'} value={confirm} dir="auto" autocomplete="new-password" onInput={(event) => setConfirm(event.currentTarget.value)} />
            </label>
            <p class="hint muted">
              {t('form.passphraseHint')}{' '}
              <button type="button" class="link" onClick={suggest}>
                {t('form.suggest')}
              </button>
            </p>
          </>
        )}
        <label class="check">
          <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.currentTarget.checked)} />
          {t('form.remember')}
        </label>
        <div class="actions">
          <button type="submit" disabled={busy}>
            {creating ? t('form.create') : t('form.signin')}
          </button>
          {!creating && dash.passkeys && (
            <button type="button" class="ghost" disabled={busy} onClick={() => void dash.signInWithPasskey(token, remember)}>
              <Icon name="lock" size={18} />
              {t('form.passkey')}
            </button>
          )}
        </div>
      </form>
      {dash.busy && (
        <p class="muted" aria-live="polite">
          {dash.busy}…
        </p>
      )}
      {dash.formError && (
        <p class="error" role="alert" dir="auto">
          {dash.formError}
        </p>
      )}
      <p class="muted">
        {creating ? t('form.toSignin') : t('form.toSetup', { repo: dash.repoName })}{' '}
        <button class="link" type="button" disabled={busy} onClick={() => dash.showForm(creating ? 'signin' : 'setup')}>
          {creating ? t('form.toSigninLink') : t('form.toSetupLink')}
        </button>
      </p>
      <details class="appearance-inline">
        <summary>{t('appearance')}</summary>
        <AppearanceSettings />
      </details>
    </Screen>
  )
}

const RELAY: Record<Dashboard['relay'], [Tone, string]> = {
  live: ['ok', 'pill.live'],
  connecting: ['busy', 'pill.connecting'],
  retrying: ['warn', 'pill.retrying'],
  off: ['off', 'pill.noRelay'],
}

function statusOf(message: OwnerMessage): Status | undefined {
  if (message.dir === 'in') return undefined
  switch (message.state) {
    case 'sending':
      return { icon: 'clock', label: t('out.sending') }
    case 'sent':
      return message.saved ? { icon: 'checks', label: t('out.saved'), tone: 'ok' } : { icon: 'check', label: t('out.sent') }
    case 'failed':
      return { icon: 'alert', label: t('out.failed'), tone: 'warn' }
    default:
      return undefined
  }
}

type Prompt = { kind: 'verify' | 'rename'; thread: string; value: string }
type Ask = { kind: 'thread'; thread: string } | { kind: 'message'; thread: string; id: string }

function Running({ dash }: { dash: Dashboard }) {
  const [selected, setSelected] = useState<string>()
  const [settings, setSettings] = useState(false)
  const [prompt, setPrompt] = useState<Prompt>()
  const [ask, setAsk] = useState<Ask>()
  const [notice, setNotice] = useState<string>()
  const thread = dash.threads.find((t) => t.id === selected)
  const messages = thread ? (dash.messages.get(thread.id) ?? []) : []
  const end = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (thread) dash.markRead(thread.id)
    end.current?.scrollIntoView({ block: 'end' })
  }, [thread?.id, messages.length])

  const run = (action: () => Promise<void>) => {
    setNotice(undefined)
    action().catch((err) => setNotice(errorText(err)))
  }
  const relay = RELAY[dash.relay]
  const view = thread ? dash.view(thread) : undefined

  return (
    <div class={`app owner ${thread ? 'has-thread' : ''}`}>
      <aside class="sidebar">
        <header class="bar">
          <Avatar name={dash.settings.name || 'S'} id={dash.fingerprint.replace(/\s/g, '')} size={36} />
          <div class="bar-title">
            <h1 dir="auto">{dash.settings.name || 'Inbox'}</h1>
            {dash.login && (
              <p class="sub muted" dir="ltr">
                @{dash.login}
              </p>
            )}
          </div>
          <IconButton icon="settings" label={t('settings')} onClick={() => setSettings(true)} />
        </header>
        <div class="status-row">
          <Pill tone={relay[0]} title={dash.relayProblem}>
            {t(relay[1])}
          </Pill>
          {dash.syncing && <Pill tone="busy">{t('pill.saving')}</Pill>}
          {!dash.syncing && dash.publishError && (
            <Pill tone="warn" title={dash.publishError}>
              {t('pill.notSaved')}
            </Pill>
          )}
          {dash.receiver !== 'off' && (
            <Pill tone={dash.receiver === 'online' ? 'ok' : dash.receiver === 'retrying' ? 'warn' : 'busy'} title={dash.receiverProblem}>
              {t('pill.files', {
                state:
                  dash.receiver === 'loading' && dash.receiverProgress !== undefined
                    ? `${Math.floor(dash.receiverProgress * 100)}%`
                    : t(`receiver.${dash.receiver}`),
              })}
            </Pill>
          )}
        </div>
        {!dash.canPublish && <Banner tone="warn">{t('banner.token')}</Banner>}
        {dash.publishError && !dash.syncing && <Banner tone="warn">{t('banner.publish', { repo: dash.repoName, why: dash.publishError })}</Banner>}
        <ul class="threads">
          {dash.threads.length === 0 && <li class="empty">{t('threads.empty')}</li>}
          {dash.threads.map((item) => {
            const shown = dash.view(item)
            return (
              <li key={item.id}>
                <button type="button" class={`thread-row ${item.id === selected ? 'selected' : ''}`} onClick={() => setSelected(item.id)}>
                  <Avatar name={shown.anonymous ? '?' : shown.name} id={item.id} />
                  <span class="thread-main">
                    <span class="thread-top">
                      <span class="thread-name" dir="auto">
                        {shown.anonymous ? `${t('thread.anonymous')} ${shown.name}` : shown.name}
                      </span>
                      {shown.verified && <Icon name="shield" size={14} />}
                      {dash.connected.has(item.id) && <span class="online" title={t('thread.online')} />}
                      <time class="muted">{item.lastTs ? formatTime(item.lastTs) : ''}</time>
                    </span>
                    <span class="thread-bottom">
                      <span class="preview muted" dir="auto">
                        {shown.blocked ? t('thread.blocked') : item.preview}
                      </span>
                      {item.unread > 0 && <span class="count">{item.unread}</span>}
                    </span>
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      </aside>

      <section class="pane">
        {!thread || !view ? (
          <div class="empty-pane">
            <Icon name="lock" size={28} />
            <p>{t('threads.choose')}</p>
          </div>
        ) : (
          <>
            <header class="bar">
              <IconButton icon="back" label={t('thread.back')} class="icon-button back" onClick={() => setSelected(undefined)} />
              <Avatar name={view.anonymous ? '?' : view.name} id={thread.id} />
              <div class="bar-title">
                <h2 dir="auto">{view.anonymous ? `${t('thread.anonymous')} ${view.name}` : view.name}</h2>
                <p class="sub">
                  {view.verified && (
                    <span class="badge ok">
                      <Icon name="shield" size={14} />
                      {t('thread.verified')}
                    </span>
                  )}
                  {view.blocked && <span class="badge warn">{t('thread.blocked')}</span>}
                  {dash.connected.has(thread.id) && <span class="muted">{t('thread.online')}</span>}
                </p>
              </div>
              <Menu
                label={t('thread.menu')}
                items={[
                  {
                    label: view.verified ? t('thread.reverify') : t('thread.verify'),
                    icon: 'shield',
                    onSelect: () => setPrompt({ kind: 'verify', thread: thread.id, value: view.verified ?? (view.anonymous ? '' : view.name) }),
                  },
                  { label: t('thread.unverify'), icon: 'shield', hidden: !dash.secretsVerified(thread.id), onSelect: () => run(() => dash.unverifyThread(thread.id)) },
                  { label: t('thread.rename'), icon: 'edit', onSelect: () => setPrompt({ kind: 'rename', thread: thread.id, value: view.anonymous ? '' : view.name }) },
                  {
                    label: view.blocked ? t('thread.unblock') : t('thread.block'),
                    icon: 'block',
                    onSelect: () => run(() => dash.blockThread(thread.id, !view.blocked)),
                  },
                  { label: t('thread.delete'), icon: 'trash', danger: true, onSelect: () => setAsk({ kind: 'thread', thread: thread.id }) },
                ]}
              />
            </header>
            <div class="scroll">
              {view.blocked && <Banner tone="warn">{t('thread.blockedNote')}</Banner>}
              <ul class="thread" aria-live="polite">
                {messages.map((message) => (
                  <Bubble
                    key={message.id}
                    mine={message.dir === 'out'}
                    ts={message.ts}
                    text={message.text}
                    files={message.files}
                    status={statusOf(message)}
                    note={message.dir === 'out' && message.state !== 'sent' ? message.note : undefined}
                    fileAction={(file) => message.dir === 'in' && <Stored dash={dash} message={message} file={file} />}
                    actions={[
                      { label: t('action.copy'), icon: 'copy', hidden: !message.text, onSelect: () => void navigator.clipboard?.writeText(message.text ?? '') },
                      {
                        label: t('message.deleteBoth'),
                        icon: 'trash',
                        danger: true,
                        onSelect: () => setAsk({ kind: 'message', thread: thread.id, id: message.id }),
                      },
                    ]}
                  />
                ))}
                <div ref={end} />
              </ul>
            </div>
            <Composer
              placeholder={t('reply.placeholder', { name: view.anonymous ? t('thread.anonymous') : view.name })}
              onSend={(text, files, options) => dash.reply(thread.id, text, files, options.onProgress)}
            />
          </>
        )}
        {notice && (
          <p class="error inline" role="alert">
            {notice}
          </p>
        )}
      </section>

      <Drawer open={settings} title={t('settings')} onClose={() => setSettings(false)}>
        <Settings dash={dash} />
      </Drawer>

      <Dialog
        open={!!prompt}
        title={prompt?.kind === 'verify' ? t('verify.title') : t('rename.title')}
        onClose={() => setPrompt(undefined)}
        actions={
          <>
            <button type="button" class="ghost" onClick={() => setPrompt(undefined)}>
              {t('action.cancel')}
            </button>
            <button
              type="button"
              disabled={prompt?.kind === 'verify' && !prompt.value.trim()}
              onClick={() => {
                const current = prompt!
                setPrompt(undefined)
                run(() => (current.kind === 'verify' ? dash.verifyThread(current.thread, current.value) : dash.renameThread(current.thread, current.value)))
              }}
            >
              {prompt?.kind === 'verify' ? t('verify.button') : t('rename.button')}
            </button>
          </>
        }
      >
        <p class="muted">{prompt?.kind === 'verify' ? t('verify.body') : t('rename.body')}</p>
        <label>
          {t('verify.label')}
          <input
            value={prompt?.value ?? ''}
            dir="auto"
            maxLength={64}
            onInput={(event) => prompt && setPrompt({ ...prompt, value: event.currentTarget.value })}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && prompt && (prompt.kind === 'rename' || prompt.value.trim())) {
                event.preventDefault()
                ;(event.currentTarget.closest('.dialog')?.querySelector('.dialog-actions button:last-child') as HTMLButtonElement | null)?.click()
              }
            }}
          />
        </label>
      </Dialog>

      <Confirm
        open={!!ask}
        title={ask?.kind === 'thread' ? t('confirm.deleteThread') : t('confirm.deleteReply')}
        body={t('confirm.deleteBody')}
        action={t('action.delete')}
        onClose={() => setAsk(undefined)}
        onConfirm={() => {
          const current = ask!
          if (current.kind === 'thread') {
            setSelected(undefined)
            run(() => dash.deleteThread(current.thread))
          } else run(() => dash.deleteMessage(current.thread, current.id))
        }}
      />
    </div>
  )
}

function Stored({ dash, message, file }: { dash: Dashboard; message: OwnerMessage; file: NonNullable<OwnerMessage['files']>[number] }) {
  const [error, setError] = useState<string>()
  const fraction = message.stored?.[toHex(file.root)] ?? 0
  if (fraction < 1) {
    return <span class="muted small">{fraction > 0 ? t('message.receiving', { percent: Math.floor(fraction * 100) }) : t('message.notReceived')}</span>
  }
  return (
    <>
      <IconButton icon="download" label={t('file.save')} onClick={() => dash.save(file).catch((err) => setError(errorText(err)))} />
      {error && <span class="error small">{error}</span>}
    </>
  )
}

function Settings({ dash }: { dash: Dashboard }) {
  const [name, setName] = useState(dash.settings.name)
  const [waku, setWaku] = useState(dash.settings.waku)
  const [ntfy, setNtfy] = useState(dash.settings.ntfy)
  const [live, setLive] = useState(dash.settings.live)
  const [saved, setSaved] = useState(false)
  const [token, setToken] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [label, setLabel] = useState('')
  const [link, setLink] = useState<string>()
  const now = Date.now() / 1000
  return (
    <>
      <AppearanceSettings />

      <form
        class="group"
        onSubmit={(event) => {
          event.preventDefault()
          void dash.saveSettings({ name: name.trim(), waku, ntfy: ntfy.trim(), live }).then(() => setSaved(true))
        }}
      >
        <h3>{t('settings.profile')}</h3>
        <label>
          {t('form.name')}
          <input value={name} dir="auto" onInput={(event) => (setName(event.currentTarget.value), setSaved(false))} />
        </label>
        <h3>{t('settings.relays')}</h3>
        <p class="muted">{t('settings.relaysHint')}</p>
        <label>
          {t('settings.ntfy')}
          <input value={ntfy} dir="ltr" placeholder="https://ntfy.sh" onInput={(event) => (setNtfy(event.currentTarget.value), setSaved(false))} />
        </label>
        <label class="check">
          <input type="checkbox" checked={waku} onChange={(event) => (setWaku(event.currentTarget.checked), setSaved(false))} />
          {t('settings.waku')}
        </label>
        <h3>{t('settings.files')}</h3>
        <label class="check">
          <input type="checkbox" checked={live} onChange={(event) => (setLive(event.currentTarget.checked), setSaved(false))} />
          {t('settings.live')}
        </label>
        <p class="hint muted">{t('settings.liveHint')}</p>
        <button type="submit">{t('settings.saveButton')}</button>
        {saved && !dash.settingsError && <p class="muted">{t('settings.saved')}</p>}
      </form>

      <section class="group">
        <h3>{t('settings.invite')}</h3>
        <p class="muted">{t('settings.inviteHint')}</p>
        <label>
          {t('settings.inviteLabel')}
          <input value={label} dir="auto" maxLength={64} onInput={(event) => setLabel(event.currentTarget.value)} />
        </label>
        <button type="button" class="ghost" disabled={!label.trim()} onClick={() => setLink(dash.inviteLink(label.trim()))}>
          <Icon name="link" size={18} />
          {t('settings.inviteCreate')}
        </button>
        {link && <textarea class="code" readOnly rows={3} value={link} dir="ltr" onFocus={(event) => event.currentTarget.select()} />}
      </section>

      <section class="group">
        <h3>{t('settings.keys')}</h3>
        <p class="muted">{t('settings.keysHint')}</p>
        <table>
          <thead>
            <tr>
              <th>{t('settings.epoch')}</th>
              <th>{t('settings.state')}</th>
              <th>{t('settings.destroyed')}</th>
            </tr>
          </thead>
          <tbody>
            {dash.epochRows.map((row) => (
              <tr key={row.epoch}>
                <td>{row.epoch}</td>
                <td>{t(`state.${row.state}`)}</td>
                <td>{formatDuration(row.shredAt - now)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {!dash.local && (
        <section class="group">
          <h3>{t('settings.github')}</h3>
          <p class="muted">{t('settings.githubHint')}</p>
          <label>
            {t('settings.newToken')}
            <input type="password" dir="ltr" value={token} autocomplete="off" onInput={(event) => setToken(event.currentTarget.value)} />
          </label>
          <button type="button" class="ghost" disabled={!token.trim()} onClick={() => void dash.replaceToken(token)}>
            {t('settings.useToken')}
          </button>
        </section>
      )}

      <section class="group">
        <h3>{t('settings.passkeys')}</h3>
        <p class="muted">{dash.passkeySlots === 0 ? t('settings.passkeysNone') : t('settings.passkeysSome', { n: dash.passkeySlots })}</p>
        {dash.passkeys && (
          <button type="button" class="ghost" onClick={() => void dash.addPasskey()}>
            <Icon name="lock" size={18} />
            {t('settings.addPasskey')}
          </button>
        )}
      </section>

      <section class="group">
        <h3>{t('settings.passphrase')}</h3>
        <label>
          {t('form.newPassphrase')}
          <input type="password" value={passphrase} autocomplete="new-password" onInput={(event) => setPassphrase(event.currentTarget.value)} />
        </label>
        <label>
          {t('form.repeat')}
          <input type="password" value={confirm} autocomplete="new-password" onInput={(event) => setConfirm(event.currentTarget.value)} />
        </label>
        <button type="button" class="ghost" disabled={!passphrase} onClick={() => void dash.changePassphrase(passphrase, confirm)}>
          {t('settings.change')}
        </button>
      </section>

      {dash.settingsNote && <p class="muted">{dash.settingsNote}</p>}
      {dash.settingsError && (
        <p class="error" role="alert" dir="auto">
          {dash.settingsError}
        </p>
      )}

      <section class="group danger-zone">
        <h3>{t('settings.browser')}</h3>
        <p class="muted">{t('settings.signOutHint')}</p>
        <button type="button" class="danger" onClick={() => void dash.signOut()}>
          {t('settings.signOut')}
        </button>
      </section>
    </>
  )
}

export type { Thread }
