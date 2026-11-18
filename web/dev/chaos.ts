// Network trouble on demand, for trying the built page against it locally.
// Only `vite preview` uses this, and only when SAYSO_CHAOS is set; nothing
// here is part of the deployed site.
//
//   SAYSO_CHAOS=parts      the first request for each WebAssembly part sends
//                          1000 bytes and then nothing, like a stalled link
//   SAYSO_CHAOS=parts500   every WebAssembly part request fails
//   SAYSO_CHAOS=ws         WebSockets (the iroh relays) never open
//   SAYSO_CHAOS=external   requests to other sites (GitHub, ntfy, Waku) hang
//   SAYSO_CHAOS=data       requests for this site's data/ hang
//   SAYSO_CHAOS=config     the request for sayso.config.json hangs
//
// Modes combine: SAYSO_CHAOS=parts,ws,external
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Plugin } from 'vite'

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '../dist')

/** Runs in the page before anything else: replaces WebSocket and fetch. */
function prelude(modes: Set<string>): string {
  return `<script>
(() => {
  const modes = new Set(${JSON.stringify([...modes])});
  console.warn('SAYSO_CHAOS active:', [...modes].join(', '));
  if (modes.has('ws')) {
    class NeverOpens extends EventTarget {
      constructor(url) {
        super();
        this.url = String(url); this.readyState = 0; this.protocol = ''; this.binaryType = 'blob'; this.bufferedAmount = 0;
        setTimeout(() => {
          this.readyState = 3;
          const error = new Event('error'); this.onerror?.(error); this.dispatchEvent(error);
          const close = new CloseEvent('close', { code: 1006, reason: 'chaos', wasClean: false });
          this.onclose?.(close); this.dispatchEvent(close);
        }, 5000);
      }
      send() { throw new DOMException('not open', 'InvalidStateError'); }
      close() {}
    }
    Object.assign(NeverOpens, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
    window.WebSocket = NeverOpens;
  }
  if (modes.has('external') || modes.has('data') || modes.has('config')) {
    const real = window.fetch.bind(window);
    window.fetch = (input, init) => {
      const url = new URL(typeof input === 'string' || input instanceof URL ? String(input) : input.url, location.href);
      const hang = (modes.has('external') && url.origin !== location.origin) || (modes.has('data') && (url.pathname.includes('/data/') || url.pathname.includes('/__data/'))) || (modes.has('config') && url.pathname.endsWith('/sayso.config.json'));
      if (!hang) return real(input, init);
      return new Promise((_resolve, reject) => {
        const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        signal?.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')));
      });
    };
  }
})();
</script>`
}

export function chaos(): Plugin {
  const modes = new Set((process.env.SAYSO_CHAOS ?? '').split(',').map((m) => m.trim()).filter(Boolean))
  const seen = new Map<string, number>()
  return {
    name: 'sayso-chaos',
    configurePreviewServer(server) {
      if (modes.size === 0) return
      server.middlewares.use(async (req, res, next) => {
        const path = (req.url ?? '/').split('?')[0]

        if (path === '/' || path === '/index.html') {
          const html = await readFile(join(dist, 'index.html'), 'utf8')
          res.setHeader('content-type', 'text/html')
          res.setHeader('cache-control', 'no-store')
          return res.end(html.replace('<head>', `<head>${prelude(modes)}`))
        }

        if (path.startsWith('/assets/wasm/') && (modes.has('parts') || modes.has('parts500'))) {
          if (modes.has('parts500')) {
            res.statusCode = 500
            return res.end('chaos')
          }
          const count = seen.get(path) ?? 0
          seen.set(path, count + 1)
          if (count === 0) {
            const body = await readFile(join(dist, path))
            res.setHeader('content-type', 'application/octet-stream')
            res.setHeader('content-length', String(body.length))
            res.setHeader('cache-control', 'no-store')
            res.write(body.subarray(0, 1000))
            // ...and then nothing, until the browser gives up on it.
            req.on('close', () => res.destroy())
            return
          }
          res.setHeader('cache-control', 'no-store')
        }
        next()
      })
    },
  }
}
