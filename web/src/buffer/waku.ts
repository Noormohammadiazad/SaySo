import type { IDecodedMessage, IDecoder, IEncoder, LightNode } from '@waku/sdk'
import type { Buffer } from './index'

const PEER_TIMEOUT_MS = 20_000
/** Read this far back before the last message seen; store nodes sync lazily. */
const OVERLAP_MS = 10 * 60_000
/**
 * The longest time window worth asking a store node for. Measured against
 * the public network: a window up to a day answers in about a second, a
 * window of weeks does not answer at all, and no window (everything the
 * node still holds for this topic) is as fast as a short one.
 */
const MAX_WINDOW_MS = 23 * 3_600_000

interface Session {
  node: LightNode
  encoder: IEncoder
  decoder: IDecoder<IDecodedMessage>
}

/**
 * The Waku network: a sender publishes with light push, and store nodes keep
 * the message for later retrieval. An item fits in one message.
 *
 * The SDK is large and only needed when the owner is away or when the
 * dashboard collects, so it is loaded on first use.
 */
export class WakuBuffer implements Buffer {
  readonly id = 'waku'
  private readonly contentTopic: string
  private session?: Promise<Session>

  constructor(topic: string) {
    this.contentTopic = `/sayso/1/sy${topic}/proto`
  }

  private connect(): Promise<Session> {
    this.session ??= (async () => {
      const { createLightNode, Protocols } = await import('@waku/sdk')
      const node = await createLightNode({ defaultBootstrap: true })
      await node.start()
      await node.waitForPeers([Protocols.LightPush, Protocols.Store], PEER_TIMEOUT_MS)
      return {
        node,
        encoder: node.createEncoder({ contentTopic: this.contentTopic }),
        decoder: node.createDecoder({ contentTopic: this.contentTopic }),
      }
    })()
    // A failed attempt must not poison every later one.
    this.session.catch(() => (this.session = undefined))
    return this.session
  }

  async put(item: Uint8Array): Promise<void> {
    const { node, encoder } = await this.connect()
    const result = await node.lightPush.send(encoder, { payload: item })
    if (result.successes.length === 0) {
      throw new Error(`waku accepted nothing: ${result.failures[0]?.error ?? 'no peer answered'}`)
    }
  }

  async drain(cursor: string | undefined, onItem: (item: Uint8Array) => Promise<void>): Promise<string | undefined> {
    const { node, decoder } = await this.connect()
    const now = Date.now()
    const from = Number(cursor ?? 0) - OVERLAP_MS
    // Recently collected: ask only for what is new. Otherwise ask for
    // everything; the receiver drops what it has already seen.
    const window = cursor && now - from <= MAX_WINDOW_MS ? { timeStart: new Date(from), timeEnd: new Date(now) } : {}
    let latest = Number(cursor ?? 0)
    for await (const page of node.store.queryGenerator([decoder], window)) {
      for (const pending of page) {
        const message = await pending
        if (!message?.payload?.length) continue
        latest = Math.max(latest, message.timestamp?.getTime() ?? 0)
        await onItem(message.payload)
      }
    }
    return latest ? String(latest) : cursor
  }
}
