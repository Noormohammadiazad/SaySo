// The smallest state container that works with Preact: an object that
// announces when it changed, and a hook that re-renders on the announcement.
import { useEffect, useState } from 'preact/hooks'

export class Observable {
  private readonly listeners = new Set<() => void>()

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  protected changed(): void {
    for (const listener of this.listeners) listener()
  }
}

export function useObservable<T extends Observable>(target: T): T {
  const [, bump] = useState(0)
  useEffect(() => target.subscribe(() => bump((n) => n + 1)), [target])
  return target
}
