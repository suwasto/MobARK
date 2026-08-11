import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import type { FileNode, FileTreeRoot } from '../../types'

/** Severity → dot class. `0` = no findings → transparent dot. */
const SEV_CLASS: Record<number, string> = {
  3: 'high',
  2: 'medium',
  1: 'low',
}

interface FileTreeProps {
  roots: FileTreeRoot[]
  /** tree path (root-relative) → worst severity rank (4..1). */
  findingFiles: Map<string, number>
  selectedPath: string | null
  /** directory path to force-open (ancestors of the auto-selected file). */
  autoExpandDir: string | null
  onOpenFile: (rootName: string, node: FileNode) => void
}

function ancestorsOf(path: string): string[] {
  const parts = path.split('/')
  const out: string[] = []
  for (let i = 1; i < parts.length; i++) out.push(parts.slice(0, i).join('/'))
  return out
}

/** One directory: `<details>` so expansion is native + cheap for 1500 nodes. */
function DirNode({
  node,
  openDirs,
  toggleDir,
  children,
}: {
  node: FileNode
  openDirs: Set<string>
  toggleDir: (path: string, open: boolean) => void
  children: ReactNode
}) {
  return (
    <details
      open={openDirs.has(node.path)}
      onToggle={(e) => toggleDir(node.path, e.currentTarget.open)}
    >
      <summary>
        <span className="tree-caret">▸</span>
        <span className="truncate">{node.name}</span>
      </summary>
      <div className="tree-nested">{children}</div>
    </details>
  )
}

/** Recursive renderer - carries the root name so file clicks know it. */
function TreeNode({
  node,
  rootName,
  ...rest
}: {
  node: FileNode
  rootName: string
  openDirs: Set<string>
  toggleDir: (path: string, open: boolean) => void
  findingFiles: Map<string, number>
  selectedPath: string | null
  onOpenFile: (rootName: string, node: FileNode) => void
}) {
  if (node.type === 'file') {
    const rank = rest.findingFiles.get(node.path) ?? 0
    const active = rest.selectedPath === node.path
    // iOS hidden binary blobs are inventory rows, not openable files - they
    // render inert (no click/keyboard, dimmed) with an explanatory tooltip.
    if (node.binary) {
      return (
        <div
          key={node.path}
          role="treeitem"
          aria-disabled
          className="file-node binary"
          title={`${node.name} - binary file, not viewable (use analysis/ + import-table findings)`}
        >
          <span className="fname">{node.name}</span>
        </div>
      )
    }
    return (
      <div
        key={node.path}
        role="treeitem"
        tabIndex={0}
        className={`file-node ${active ? 'active' : ''}`}
        title={node.path}
        onClick={() => rest.onOpenFile(rootName, node)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            rest.onOpenFile(rootName, node)
          }
        }}
      >
        <span className="fname">{node.name}</span>
        <span className={`fdot ${rank ? SEV_CLASS[rank] : 'none'}`} />
      </div>
    )
  }
  return (
    <DirNode node={node} openDirs={rest.openDirs} toggleDir={rest.toggleDir}>
      {node.children.map((child) => (
        <TreeNode key={child.path} node={child} rootName={rootName} {...rest} />
      ))}
    </DirNode>
  )
}

export function FileTree({
  roots,
  findingFiles,
  selectedPath,
  autoExpandDir,
  onOpenFile,
}: FileTreeProps) {
  const [openDirs, setOpenDirs] = useState<Set<string>>(new Set())

  // Keep the auto-selected file's ancestors open whenever it changes.
  useEffect(() => {
    if (!autoExpandDir) return
    setOpenDirs((prev) => {
      const next = new Set(prev)
      for (const a of ancestorsOf(autoExpandDir)) next.add(a)
      return next
    })
  }, [autoExpandDir])

  const toggleDir = (path: string, open: boolean) => {
    setOpenDirs((prev) => {
      const next = new Set(prev)
      if (open) next.add(path)
      else next.delete(path)
      return next
    })
  }

  return (
    <div className="file-tree" role="tree">
      {roots.map((root) => (
        <div key={root.name}>
          <div className="tree-root-label">
            {root.name}
            {root.truncated && (
              <span className="tree-truncated"> · truncated</span>
            )}
          </div>
          {root.tree.map((child) => (
            <TreeNode
              key={child.path}
              node={child}
              rootName={root.name}
              openDirs={openDirs}
              toggleDir={toggleDir}
              findingFiles={findingFiles}
              selectedPath={selectedPath}
              onOpenFile={onOpenFile}
            />
          ))}
        </div>
      ))}
    </div>
  )
}
