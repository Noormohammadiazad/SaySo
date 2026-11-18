import { useEffect, useRef, useState } from 'preact/hooks'
import { errorText } from './format'
import { Icon, IconButton } from './kit'
import { formatBytes, t } from './prefs'

export interface SendOptions {
  signal: AbortSignal
  onProgress: (fraction: number) => void
}

/**
 * Write, attach, send. Enter sends and Shift+Enter starts a new line (an
 * input method composing a word keeps Enter for itself). Files can be
 * picked, pasted, or dropped anywhere on the page; each shows as a card
 * that can be removed, and while it is being encrypted, cancelled.
 */
export function Composer({ placeholder, onSend, busy }: {
  placeholder: string
  onSend: (text: string, files: File[], options: SendOptions) => Promise<void>
  /** Something the view is doing on its own, said under the box. */
  busy?: string
}) {
  const [text, setText] = useState('')
  const [files, setFiles] = useState<File[]>([])
  const [sending, setSending] = useState<AbortController>()
  const [progress, setProgress] = useState<number>()
  const [error, setError] = useState<string>()
  const [dragging, setDragging] = useState(false)
  const box = useRef<HTMLTextAreaElement>(null)
  const picker = useRef<HTMLInputElement>(null)

  const add = (list: FileList | File[] | null | undefined): void => {
    const picked = [...(list ?? [])]
    if (picked.length) setFiles((current) => [...current, ...picked])
  }

  // The whole page is a drop target while this is on screen.
  useEffect(() => {
    let depth = 0
    const hasFiles = (event: DragEvent): boolean => [...(event.dataTransfer?.types ?? [])].includes('Files')
    const enter = (event: DragEvent): void => {
      if (!hasFiles(event)) return
      depth++
      setDragging(true)
    }
    const leave = (event: DragEvent): void => {
      if (!hasFiles(event)) return
      if (--depth <= 0) setDragging(false)
    }
    const over = (event: DragEvent): void => {
      if (hasFiles(event)) event.preventDefault()
    }
    const drop = (event: DragEvent): void => {
      if (!hasFiles(event)) return
      event.preventDefault()
      depth = 0
      setDragging(false)
      add(event.dataTransfer?.files)
    }
    window.addEventListener('dragenter', enter)
    window.addEventListener('dragleave', leave)
    window.addEventListener('dragover', over)
    window.addEventListener('drop', drop)
    return () => {
      window.removeEventListener('dragenter', enter)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('dragover', over)
      window.removeEventListener('drop', drop)
    }
  }, [])

  // Grow with the text, up to a few lines.
  useEffect(() => {
    const el = box.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 180)}px`
  }, [text])

  const ready = !sending && (text.trim().length > 0 || files.length > 0)
  const submit = async (): Promise<void> => {
    if (!ready) return
    const controller = new AbortController()
    setSending(controller)
    setError(undefined)
    setProgress(files.length ? 0 : undefined)
    try {
      await onSend(text, files, { signal: controller.signal, onProgress: setProgress })
      setText('')
      setFiles([])
    } catch (err) {
      if (!controller.signal.aborted) setError(errorText(err))
    } finally {
      setSending(undefined)
      setProgress(undefined)
      box.current?.focus()
    }
  }

  return (
    <form
      class="composer"
      onSubmit={(event) => {
        event.preventDefault()
        void submit()
      }}
    >
      {dragging && (
        <div class="dropzone" aria-hidden="true">
          <Icon name="attach" size={28} />
          {t('composer.drop')}
        </div>
      )}
      {files.length > 0 && (
        <ul class="file-cards">
          {files.map((file, index) => (
            <li class="file-card" key={`${file.name}-${index}`}>
              <Icon name="file" />
              <span class="file-name" dir="auto">
                {file.name}
              </span>
              <span class="muted">{formatBytes(file.size)}</span>
              {sending ? (
                progress !== undefined && <span class="muted">{t('file.encrypting', { percent: Math.floor(progress * 100) })}</span>
              ) : (
                <IconButton icon="close" label={t('file.remove', { name: file.name })} onClick={() => setFiles(files.filter((_, i) => i !== index))} />
              )}
            </li>
          ))}
          {sending && progress !== undefined && (
            <li class="file-progress">
              <div class="progress" role="progressbar" aria-valuenow={Math.floor(progress * 100)} aria-valuemin={0} aria-valuemax={100}>
                <span style={{ width: `${Math.floor(progress * 100)}%` }} />
              </div>
              <button type="button" class="ghost small" onClick={() => sending.abort()}>
                {t('file.cancel')}
              </button>
            </li>
          )}
        </ul>
      )}
      <div class="composer-row">
        <IconButton icon="attach" label={t('composer.attach')} onClick={() => picker.current?.click()} disabled={!!sending} />
        <input ref={picker} type="file" multiple hidden onChange={(event) => (add(event.currentTarget.files), (event.currentTarget.value = ''))} />
        <textarea
          ref={box}
          rows={1}
          dir="auto"
          value={text}
          placeholder={placeholder}
          aria-label={placeholder}
          onInput={(event) => setText(event.currentTarget.value)}
          onPaste={(event) => {
            if (event.clipboardData?.files.length) {
              event.preventDefault()
              add(event.clipboardData.files)
            }
          }}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
              event.preventDefault()
              void submit()
            }
          }}
        />
        <button type="submit" class="send" aria-label={t('composer.send')} title={t('composer.send')} disabled={!ready}>
          <Icon name="send" />
        </button>
      </div>
      {(error || busy) && <p class={error ? 'error' : 'muted hint'} role={error ? 'alert' : 'status'}>{error ?? busy}</p>}
    </form>
  )
}
