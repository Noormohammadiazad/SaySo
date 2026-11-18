// Language and theme: detected on first visit, switchable at once, kept in
// this browser. Applied to <html> before the first render, so the page
// never flashes in the wrong direction or colours.
import { Observable } from './store'

export type Locale = 'en' | 'fa'
export type Theme = 'system' | 'light' | 'dark'

type Dict = Record<string, string>
const dicts: Record<Locale, Dict> = { en: {}, fa: {} }

/** Register a view's strings; each view brings its own, so the sender's bundle carries none of the dashboard's. */
export function addStrings(en: Dict, fa: Dict): void {
  Object.assign(dicts.en, en)
  Object.assign(dicts.fa, fa)
}

const stored = (key: string): string | null => {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}
const store = (key: string, value: string): void => {
  try {
    localStorage.setItem(key, value)
  } catch {
    // Private mode: the choice lasts for this page only.
  }
}

function detectLocale(): Locale {
  const saved = stored('sayso.locale')
  if (saved === 'en' || saved === 'fa') return saved
  return (navigator.languages ?? [navigator.language]).some((lang) => /^fa\b/i.test(lang)) ? 'fa' : 'en'
}

class Prefs extends Observable {
  locale: Locale = detectLocale()
  theme: Theme = ((): Theme => {
    const saved = stored('sayso.theme')
    return saved === 'light' || saved === 'dark' ? saved : 'system'
  })()

  apply(): void {
    const root = document.documentElement
    root.lang = this.locale
    root.dir = this.locale === 'fa' ? 'rtl' : 'ltr'
    if (this.theme === 'system') delete root.dataset.theme
    else root.dataset.theme = this.theme
  }

  setLocale(locale: Locale): void {
    this.locale = locale
    store('sayso.locale', locale)
    this.apply()
    this.changed()
  }

  setTheme(theme: Theme): void {
    this.theme = theme
    store('sayso.theme', theme)
    this.apply()
    this.changed()
  }
}

export const prefs = new Prefs()

/** The string for `key` in the current language, with `{name}` placeholders filled. */
export function t(key: string, vars?: Record<string, string | number>): string {
  const text = dicts[prefs.locale][key] ?? dicts.en[key] ?? key
  return vars ? text.replace(/\{(\w+)\}/g, (_, name: string) => (name in vars ? formatValue(vars[name]) : `{${name}}`)) : text
}

const formatValue = (value: string | number): string => (typeof value === 'number' ? formatNumber(value) : value)

export const formatNumber = (value: number): string => value.toLocaleString(prefs.locale === 'fa' ? 'fa-IR' : 'en-US')

export function formatBytes(bytes: number): string {
  const units = prefs.locale === 'fa' ? ['بایت', 'ک‌ب', 'م‌ب', 'گ‌ب', 'ت‌ب'] : ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  const shown = unit === 0 || value >= 100 ? Math.round(value) : Math.round(value * 10) / 10
  return `${formatNumber(shown)} ${units[unit]}`
}

export function formatTime(ms: number): string {
  const date = new Date(ms)
  const today = new Date().toDateString() === date.toDateString()
  const locale = prefs.locale === 'fa' ? 'fa-IR' : 'en-US'
  return date.toLocaleString(locale, today ? { hour: '2-digit', minute: '2-digit' } : { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function formatDuration(seconds: number): string {
  if (seconds < 3600) return t('duration.minutes', { n: Math.max(1, Math.round(seconds / 60)) })
  if (seconds < 2 * 86_400) return t('duration.hours', { n: Math.round(seconds / 3600) })
  return t('duration.days', { n: Math.round(seconds / 86_400) })
}
