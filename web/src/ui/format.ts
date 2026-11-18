// Kept for code that is not about display: an error's message in a sentence.
export const errorText = (err: unknown): string => (err instanceof Error ? err.message : String(err))

export { formatBytes, formatDuration, formatTime } from './prefs'
