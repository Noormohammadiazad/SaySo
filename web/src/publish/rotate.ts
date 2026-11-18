// The workflow's file name, moved on with every commit to main. GitHub
// numbers a workflow's runs by its file path, so a path that never existed
// starts at run #1. Same rule as the repository's scripts/rotate-workflow.mjs:
// <slug of its name:>-<UTC date>-<UTC time>.yml, always later than now and
// than the current name.

export const WORKFLOW_DIR = '.github/workflows/'

export function workflowSlug(content: string): string {
  const declared = /^name:\s*['"]?(.+?)['"]?\s*$/m.exec(content)?.[1] ?? 'workflow'
  return declared.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'workflow'
}

const stampOf = (date: Date): string => date.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)

function dateOf(stamp: string): Date {
  const [d, t] = stamp.split('-')
  return new Date(`${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}T${t.slice(0, 2)}:${t.slice(2, 4)}:${t.slice(4, 6)}Z`)
}

/** The next name for the workflow at `currentPath`, whose text is `content`. */
export function rotatedWorkflowName(currentPath: string, content: string, now: Date = new Date()): string {
  const current = currentPath.split('/').pop()!
  let when = now
  const previous = /-(\d{8}-\d{6})\.ya?ml$/.exec(current)?.[1]
  if (previous && stampOf(when) <= previous) when = new Date(dateOf(previous).getTime() + 1000)
  return `${WORKFLOW_DIR}${workflowSlug(content)}-${stampOf(when)}.yml`
}
