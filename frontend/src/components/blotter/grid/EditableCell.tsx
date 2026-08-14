// Double-click a cell to edit its value.  Enter commits, Esc cancels,
// blur commits (matches DevExpress GridView default).  The commit
// callback is dispatched via a custom event so the mock data store can
// update without wiring a prop chain through every column.

import { useEffect, useRef, useState } from 'react';

export interface CellCommitEvent {
  rowId: string;
  colId: string;
  value: number;
}

// Datetime-editor variant.  Renders the value as a human-readable
// "YYYY-MM-DD HH:MM:SS" and, on double-click, swaps to an
// <input type="datetime-local">.  Value is nanoseconds since epoch;
// commit converts local-time back to ns.
export function DateEditableCell({
  ns, rowId, colId, canEdit,
}: {
  ns: number;
  rowId: string;
  colId: string;
  canEdit: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select?.();
    }
  }, [editing]);

  const display = formatDateShort(ns);
  if (!editing) {
    return (
      <span
        className={`mono ${canEdit ? 'editable' : 'dim'}`}
        onDoubleClick={(e) => {
          if (!canEdit) return;
          e.stopPropagation();
          setDraft(toLocalDateTimeInputValue(ns));
          setEditing(true);
        }}
        title={canEdit ? 'Double-click to edit date/time' : display}
      >
        {display}
      </span>
    );
  }

  const commit = () => {
    // draft is "YYYY-MM-DDTHH:mm" in the user's LOCAL timezone.
    const t = Date.parse(draft);
    if (!Number.isNaN(t) && t * 1_000_000 !== ns) {
      dispatchCommit({ rowId, colId, value: t * 1_000_000 });
    }
    setEditing(false);
  };

  return (
    <input
      ref={inputRef}
      type="datetime-local"
      className="cell-edit cell-edit-date"
      step={1}
      value={draft}
      onChange={e => setDraft(e.target.value)}
      onKeyDown={e => {
        if (e.key === 'Enter') { e.stopPropagation(); commit(); }
        else if (e.key === 'Escape') { e.stopPropagation(); setEditing(false); }
      }}
      onBlur={commit}
      onClick={e => e.stopPropagation()}
    />
  );
}

function pad(n: number) { return String(n).padStart(2, '0'); }

function toLocalDateTimeInputValue(ns: number): string {
  // datetime-local expects "YYYY-MM-DDTHH:mm" in *local* time.
  const d = new Date(ns / 1_000_000);
  return (
    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    'T' + pad(d.getHours()) + ':' + pad(d.getMinutes())
  );
}
function formatDateShort(ns: number): string {
  const d = new Date(ns / 1_000_000);
  return (
    pad(d.getMonth() + 1) + '/' + pad(d.getDate()) + ' ' +
    pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
  );
}

export function dispatchCommit(evt: CellCommitEvent) {
  window.dispatchEvent(new CustomEvent<CellCommitEvent>('cell-commit', { detail: evt }));
}

interface Props {
  value: number;
  rowId: string;
  colId: string;
  canEdit: boolean;
  format: (n: number) => string;
  parse: (s: string) => number | null;
}

export function EditableCell({ value, rowId, colId, canEdit, format, parse }: Props) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editing]);

  if (!editing) {
    return (
      <span
        className={`num ${canEdit ? 'editable' : 'dim'}`}
        onDoubleClick={(e) => {
          if (!canEdit) return;
          e.stopPropagation();
          setDraft(String(value));
          setEditing(true);
        }}
        title={canEdit ? 'Double-click to edit' : undefined}
      >
        {format(value)}
      </span>
    );
  }

  const commit = () => {
    const parsed = parse(draft.trim());
    if (parsed != null && parsed !== value) {
      dispatchCommit({ rowId, colId, value: parsed });
    }
    setEditing(false);
  };

  return (
    <input
      ref={inputRef}
      className="cell-edit"
      value={draft}
      onChange={e => setDraft(e.target.value)}
      onKeyDown={e => {
        if (e.key === 'Enter') { e.stopPropagation(); commit(); }
        else if (e.key === 'Escape') { e.stopPropagation(); setEditing(false); }
      }}
      onBlur={commit}
      onClick={e => e.stopPropagation()}
      inputMode="decimal"
    />
  );
}
