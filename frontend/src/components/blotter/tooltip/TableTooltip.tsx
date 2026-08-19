// Rich hover tooltip.  Wraps its trigger in a <span> holding the floating
// ref + event handlers — simpler and more robust than cloneElement, which
// breaks with TanStack's flexRender + React 19 ref semantics.

import {
  useFloating,
  useHover,
  useInteractions,
  useDismiss,
  useFocus,
  useRole,
  offset, flip, shift, autoUpdate,
  FloatingPortal,
  safePolygon,
} from '@floating-ui/react';
import { useState } from 'react';
import type { ReactNode } from 'react';

interface Props {
  content: ReactNode;
  children: ReactNode;
  placement?: 'top' | 'bottom' | 'right' | 'left';
  openDelayMs?: number;
  className?: string;
}

export function TableTooltip({
  content, children,
  placement = 'right',
  openDelayMs = 120,
  className,
}: Props) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement,
    middleware: [offset(8), flip(), shift({ padding: 8 })],
    whileElementsMounted: autoUpdate,
  });

  const hover = useHover(context, {
    handleClose: safePolygon(),
    delay: { open: openDelayMs, close: 100 },
    move: false,
  });
  const focus = useFocus(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'tooltip' });

  const { getReferenceProps, getFloatingProps } = useInteractions([
    hover, focus, dismiss, role,
  ]);

  return (
    <>
      <span
        ref={refs.setReference}
        className={`tooltip-trigger ${className ?? ''}`}
        {...getReferenceProps()}
      >
        {children}
      </span>
      {open && (
        <FloatingPortal>
          <div
            ref={refs.setFloating}
            className="tooltip-panel"
            style={floatingStyles}
            {...getFloatingProps()}
          >
            {content}
          </div>
        </FloatingPortal>
      )}
    </>
  );
}
