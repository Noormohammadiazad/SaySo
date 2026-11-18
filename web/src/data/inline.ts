// What the deploy workflow writes into index.html itself, so the first
// paint needs no request beyond the page and its script: the site's
// configuration and the owner's signed owner.json. A network that stalls on
// every new request (some do, for seconds at a time) cannot hold the page up.
//
// It is only a head start. The owner's document is verified like any other
// copy, and the sender re-reads the live one in the background.

export interface SiteConfig {
  /** `owner/name`. Written by the deploy workflow; needed on custom domains. */
  repo?: string
  /** GitHub API base URL; only the local stand-ins change it. */
  api?: string
  /** The ntfy relay a new inbox starts with; only the local stand-ins change it. */
  ntfy?: string
  /** Use the local stand-ins. Set only by `vite preview` under SAYSO_LOCAL=1. */
  local?: boolean
}

export interface InlineData {
  config?: SiteConfig
  /** The text of owner.json when the page was deployed. */
  owner?: string
  /** When the page was deployed, Unix ms. */
  at?: number
}

let cached: InlineData | undefined

export function inlineData(): InlineData {
  if (cached) return cached
  cached = {}
  try {
    const text = document.getElementById('sayso-data')?.textContent?.trim()
    if (text) cached = JSON.parse(text) as InlineData
  } catch {
    // A page without the block, or a damaged one: fall back to the network.
  }
  return cached
}
