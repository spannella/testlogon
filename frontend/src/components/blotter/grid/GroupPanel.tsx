// Group panel — vertical tree view of the current grouping hierarchy.
// Each row is a grouping level indented by depth; drop a header onto
// a row to insert at that position, or into the empty area at the
// bottom to append.  Drag rows up/down within the tree to reorder.

import { useState } from 'react';
import type { Table } from '@tanstack/react-table';
import type { Order } from '../types';

interface Props {
  table: Table<Order>;
  onDropColumn: (colId: string) => void;
  onClearDragState?: () => void;
}

const GROUP_PREFIX = 'GROUP:';
const HEADER_PREFIX = 'HEADER:';

type DropTarget = { colId: string; side: 'above' | 'below' } | 'tail' | null;

// onDropColumn is kept in the props signature so Blotter can keep its
// existing call-site; we now handle the drop internally (append to the
// grouping array) since the tail zone gives that same behavior.  Wired
// through in case a caller wants to intercept.
export function GroupPanel({ table, onDropColumn: _onDropColumn, onClearDragState }: Props) {
  const grouping = table.getState().grouping;
  const [over, setOver] = useState(false);
  const [target, setTarget] = useState<DropTarget>(null);

  // Compute insert position given the source id and current target,
  // returning the new grouping array.
  const applyDrop = (srcId: string) => {
    table.setGrouping(prev => {
      const without = prev.filter(id => id !== srcId);
      if (target === 'tail' || target == null) return [...without, srcId];
      let idx = without.indexOf(target.colId);
      if (idx === -1) idx = without.length;
      if (target.side === 'below') idx += 1;
      without.splice(idx, 0, srcId);
      return without;
    });
  };

  const parseDrop = (e: React.DragEvent) => {
    const payload = e.dataTransfer.getData('text/plain');
    if (payload.startsWith(GROUP_PREFIX)) return payload.slice(GROUP_PREFIX.length);
    if (payload.startsWith(HEADER_PREFIX)) return payload.slice(HEADER_PREFIX.length);
    return null;
  };

  const clearAll = () => {
    setOver(false);
    setTarget(null);
    onClearDragState?.();
  };

  return (
    <div
      className={`group-panel ${grouping.length ? 'tree' : ''} ${over ? 'over' : ''}`}
      onDragEnter={e => {
        if (e.dataTransfer.types.includes('text/plain')) setOver(true);
      }}
      onDragOver={e => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
        setOver(true);
      }}
      onDragLeave={e => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
          setOver(false);
          setTarget(null);
        }
      }}
      onDrop={e => {
        e.preventDefault();
        const srcId = parseDrop(e);
        clearAll();
        if (srcId) applyDrop(srcId);
      }}
    >
      {grouping.length === 0 ? (
        <span className="group-empty">
          Drag a column header here to group by it
        </span>
      ) : (
        <>
          <div className="group-tree-title">Grouped by</div>
          <div className="group-tree">
            {grouping.map((colId, depth) => {
              const col = table.getColumn(colId);
              const targetCls =
                target && target !== 'tail' && target.colId === colId
                  ? `drop-${target.side}`
                  : '';
              return (
                <div
                  key={colId}
                  className={`group-tree-row ${targetCls}`}
                  onDragOver={e => {
                    if (!e.dataTransfer.types.includes('text/plain')) return;
                    e.preventDefault();
                    e.stopPropagation();
                    e.dataTransfer.dropEffect = 'move';
                    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                    const side: 'above' | 'below' =
                      (e.clientY - rect.top) < rect.height / 2 ? 'above' : 'below';
                    setTarget(prev =>
                      prev && prev !== 'tail' && prev.colId === colId && prev.side === side
                        ? prev
                        : { colId, side }
                    );
                  }}
                  onDrop={e => {
                    const srcId = parseDrop(e);
                    e.preventDefault();
                    e.stopPropagation();
                    clearAll();
                    if (srcId && srcId !== colId) applyDrop(srcId);
                  }}
                >
                  {/* vertical rails for parent depths + a branch line for this depth */}
                  <span className="tree-rails">
                    {Array.from({ length: depth }).map((_, k) => (
                      <span key={k} className="tree-rail" />
                    ))}
                    <span className="tree-rail branch" />
                  </span>
                  <span
                    className="group-tree-name"
                    draggable
                    onDragStart={e => {
                      e.dataTransfer.setData('text/plain', GROUP_PREFIX + colId);
                      e.dataTransfer.effectAllowed = 'move';
                    }}
                    onDragEnd={clearAll}
                    title="Drag to reorder · drag out of the panel to un-group"
                  >
                    {String(col?.columnDef.header ?? colId)}
                    <span className="group-tree-meta">{colId}</span>
                  </span>
                  <button
                    className="group-x"
                    onClick={() =>
                      table.setGrouping(g => g.filter(id => id !== colId))
                    }
                    aria-label={`Ungroup ${colId}`}
                  >×</button>
                </div>
              );
            })}
            <div
              className={`group-tree-tail ${target === 'tail' ? 'drop-here' : ''}`}
              onDragOver={e => {
                if (!e.dataTransfer.types.includes('text/plain')) return;
                e.preventDefault();
                e.stopPropagation();
                e.dataTransfer.dropEffect = 'copy';
                setTarget('tail');
              }}
              onDrop={e => {
                const srcId = parseDrop(e);
                e.preventDefault();
                e.stopPropagation();
                clearAll();
                if (srcId) {
                  table.setGrouping(prev => {
                    const without = prev.filter(id => id !== srcId);
                    return [...without, srcId];
                  });
                }
              }}
            >
              {/* rails for a would-be child at depth = grouping.length */}
              <span className="tree-rails">
                {Array.from({ length: grouping.length }).map((_, k) => (
                  <span key={k} className="tree-rail dim" />
                ))}
                <span className="tree-rail branch dim" />
              </span>
              <span className="group-tail-hint">
                drop a header here for a deeper level
              </span>
            </div>
          </div>
          <button
            className="group-clear"
            onClick={() => table.resetGrouping()}
          >clear all</button>
        </>
      )}
    </div>
  );
}

export { GROUP_PREFIX, HEADER_PREFIX };
