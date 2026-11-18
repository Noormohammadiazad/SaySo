import type { ComponentChildren } from 'preact'
import type { FileRef } from '../core'
import { Icon, Menu, type IconName, type MenuItem } from './kit'
import { formatBytes, formatTime, t } from './prefs'

export interface Status {
  icon: IconName
  label: string
  tone?: 'ok' | 'warn'
}

/** One message: its text, its files, when, how far it got, and what can be done with it. */
export function Bubble({
  mine,
  ts,
  text,
  files,
  status,
  note,
  fileAction,
  actions,
}: {
  mine: boolean
  ts: number
  text?: string
  files?: FileRef[]
  status?: Status
  note?: string
  fileAction?: (file: FileRef) => ComponentChildren
  actions?: MenuItem[]
}) {
  return (
    <li class={`bubble-row ${mine ? 'mine' : 'theirs'}`}>
      <div class="bubble">
        {text && (
          <p class="bubble-text" dir="auto">
            {text}
          </p>
        )}
        {files?.map((file) => (
          <div class="attachment" key={file.name + file.size}>
            <Icon name="file" />
            <div class="attachment-text">
              <span class="file-name" dir="auto">
                {file.name}
              </span>
              <span class="muted">{formatBytes(file.size)}</span>
            </div>
            {fileAction?.(file)}
          </div>
        ))}
        <footer class="bubble-meta">
          <time dateTime={new Date(ts).toISOString()}>{formatTime(ts)}</time>
          {status && (
            <span class={`status ${status.tone ?? ''}`} title={status.label}>
              <Icon name={status.icon} size={15} />
              <span class="status-label">{status.label}</span>
            </span>
          )}
        </footer>
        {note && <p class="bubble-note">{note}</p>}
      </div>
      {actions && <Menu label={t('message.actions')} items={actions} align={mine ? 'end' : 'start'} />}
    </li>
  )
}
