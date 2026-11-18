import { render, type ComponentChild } from 'preact'
import { quietAborts } from './boot'
import { SenderApp } from './sender/SenderApp'
import { prefs } from './ui/prefs'
import './styles.css'

prefs.apply()

// Relays and the Waku network cancel requests in the background all the
// time; those are handled where they matter and must not surface as errors.
quietAborts()

// Two views. The sender view is in this bundle, so a visitor needs nothing
// else to start; the dashboard (#/owner) is a separate chunk only its owner
// downloads. Everything else, including the #k= and #i= links senders open,
// is the sender view.
const isOwner = location.hash.startsWith('#/owner')
const root = document.getElementById('app')!
// The page's own "Loading…" note stays until a view replaces it, so a stalled
// chunk download still says something (see index.html).
const show = (view: ComponentChild): void => {
  root.textContent = ''
  render(view, root)
}
if (isOwner) {
  import('./owner/OwnerApp').then(
    ({ OwnerApp }) => show(<OwnerApp />),
    (err: unknown) => {
      root.innerHTML = '<main class="column screen"><h1>The dashboard did not load</h1><p></p><button>Try again</button></main>'
      root.querySelector('p')!.textContent = `Loading its script failed: ${err instanceof Error ? err.message : String(err)}`
      root.querySelector('button')!.onclick = () => location.reload()
    },
  )
} else {
  show(<SenderApp />)
}
window.addEventListener('hashchange', () => {
  if (location.hash.startsWith('#/owner') !== isOwner) location.reload()
})
