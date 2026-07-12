import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  DndContext,
  closestCenter,
  type DragEndEvent,
  type DragStartEvent,
  DragOverlay,
  useDraggable,
  useDroppable,
  PointerSensor,
  KeyboardSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import { CSS } from "@dnd-kit/utilities";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { UserProfileLink } from "@/components/shared/UserProfileLink";
import {
  setBoardTicketStatus,
  type Board,
  type BoardColumn,
  type BoardTicket,
  type TicketStatus,
  type TicketStatusWritable,
} from "@/api/endpoints/tickets";

// ─── Status transition rules (must mirror backend _STATUS_TRANSITIONS) ──
const VALID_TRANSITIONS: Record<string, string[]> = {
  open: ["in_progress", "done"],
  in_progress: ["waiting_on_user", "done", "open"],
  waiting_on_user: ["in_progress", "done", "open"],
  done: ["open"],
};

// Moving a card BACK to an "open" status requires the "reopened" command.
function statusToWritable(status: string): TicketStatusWritable {
  if (status === "open") return "reopened";
  return status as TicketStatus;
}

const COLUMN_DOT_COLORS: Record<string, string> = {
  open: "bg-blue-500",
  in_progress: "bg-purple-500",
  waiting_on_user: "bg-yellow-500",
  done: "bg-green-500",
};

// ─── Card UI: assignee, priority/complexity, labels (TKB-013) ─────────

const MAX_LABEL_CHIPS = 3;

const COMPLEXITY_STYLES: Record<string, { label: string; className: string }> = {
  low: { label: "Low", className: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300" },
  medium: { label: "Medium", className: "bg-amber-500/15 text-amber-700 dark:text-amber-300" },
  high: { label: "High", className: "bg-rose-500/15 text-rose-700 dark:text-rose-300" },
};

function PriorityPill({ complexity }: { complexity?: string | null }) {
  if (!complexity) return null;
  const meta = COMPLEXITY_STYLES[complexity] ?? {
    label: complexity,
    className: "bg-muted text-muted-foreground",
  };
  return (
    <span className={cn("rounded-full px-2 py-0.5 text-[10px] font-medium", meta.className)}>
      {meta.label}
    </span>
  );
}

function LabelChips({ labels }: { labels?: string[] }) {
  const visible = (labels ?? []).filter((l) => !l.startsWith("complexity:"));
  if (!visible.length) return null;
  const shown = visible.slice(0, MAX_LABEL_CHIPS);
  const overflow = visible.length - shown.length;
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1">
      {shown.map((label) => (
        <span
          key={label}
          className="max-w-[7rem] truncate rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
          title={label}
        >
          {label}
        </span>
      ))}
      {overflow > 0 && (
        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
          +{overflow}
        </span>
      )}
    </div>
  );
}

function CardBody({ ticket }: { ticket: BoardTicket }) {
  const assignee = ticket.assigned_to_sub || ticket.assigned_admin_sub || null;
  return (
    <>
      <div className="flex items-start gap-2">
        <p className="flex-1 text-sm font-medium leading-snug">{ticket.subject}</p>
        <PriorityPill complexity={ticket.complexity} />
      </div>
      {assignee && (
        <div className="mt-2 text-[10px] text-muted-foreground truncate">
          Assignee:{" "}
          <UserProfileLink
            userId={assignee}
            displayName={assignee.length > 12 ? assignee.slice(0, 10) + "…" : assignee}
            className="hover:underline"
            ariaLabel={`Open ${assignee} profile`}
          />
        </div>
      )}
      <LabelChips labels={ticket.labels} />
    </>
  );
}

// ─── DraggableTicketCard ──────────────────────────────────────────

function DraggableTicketCard({ ticket }: { ticket: BoardTicket }) {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: ticket.ticket_id,
    data: { status: ticket.status },
  });

  const style: React.CSSProperties = {
    transform: CSS.Translate.toString(transform),
  };

  return (
    <div
      ref={setNodeRef}
      {...attributes}
      {...listeners}
      style={style}
      data-testid={`kanban-card-${ticket.ticket_id}`}
      className={cn(
        "bg-card rounded-lg border p-3 cursor-grab active:cursor-grabbing shadow-sm",
        isDragging && "opacity-50 shadow-lg ring-2 ring-primary",
      )}
    >
      <CardBody ticket={ticket} />
    </div>
  );
}

// ─── KanbanColumn ─────────────────────────────────────────────────

function KanbanColumn({
  column,
  tickets,
}: {
  column: BoardColumn;
  tickets: BoardTicket[];
}) {
  // Droppable id is the column's status_key so a drop maps to a real status.
  const { setNodeRef, isOver } = useDroppable({ id: column.status_key });
  const dotColor = column.color ?? COLUMN_DOT_COLORS[column.status_key] ?? "bg-gray-400";

  return (
    <div
      ref={setNodeRef}
      data-testid={`kanban-column-${column.status_key}`}
      className={cn(
        "w-72 shrink-0 rounded-lg bg-muted/50 p-3",
        isOver && "ring-2 ring-primary bg-primary/5",
      )}
    >
      <div className="flex items-center gap-2 mb-3">
        <div className={cn("w-3 h-3 rounded-full", dotColor.startsWith("bg-") ? dotColor : "")} style={dotColor.startsWith("#") ? { backgroundColor: dotColor } : undefined} />
        <h3 className="text-sm font-semibold">{column.title}</h3>
        {column.wip_limit ? (
          <span className="text-[10px] text-muted-foreground">/ {column.wip_limit}</span>
        ) : null}
        <Badge variant="outline" className="ml-auto" data-testid={`kanban-count-${column.status_key}`}>
          {tickets.length}
        </Badge>
      </div>
      <div className="space-y-2 min-h-[100px]">
        {tickets.map((ticket) => (
          <DraggableTicketCard key={ticket.ticket_id} ticket={ticket} />
        ))}
      </div>
    </div>
  );
}

// ─── BoardKanban ──────────────────────────────────────────────────

interface BoardKanbanProps {
  board: Board;
  tickets: BoardTicket[];
  /** React Query key the ticket list is cached under, for optimistic updates. */
  ticketsQueryKey: unknown[];
}

interface TicketListCache {
  items: BoardTicket[];
  next_cursor?: string | null;
}

export function BoardKanban({ board, tickets, ticketsQueryKey }: BoardKanbanProps) {
  const queryClient = useQueryClient();
  const [activeTicket, setActiveTicket] = useState<BoardTicket | null>(null);

  const columns = useMemo(
    () => [...(board.columns ?? [])].sort((a, b) => (a.order ?? 0) - (b.order ?? 0)),
    [board.columns],
  );

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor),
  );

  const updateStatusMut = useMutation({
    mutationFn: ({ ticketId, status }: { ticketId: string; status: string }) =>
      setBoardTicketStatus(board.board_id, ticketId, statusToWritable(status)),
    // Optimistic move (TKB-012): apply the new status in cache immediately.
    onMutate: async ({ ticketId, status }) => {
      await queryClient.cancelQueries({ queryKey: ticketsQueryKey });
      const previous = queryClient.getQueryData<TicketListCache>(ticketsQueryKey);
      queryClient.setQueryData<TicketListCache>(ticketsQueryKey, (old) => {
        if (!old) return old;
        return {
          ...old,
          items: old.items.map((t) =>
            t.ticket_id === ticketId ? { ...t, status: status as TicketStatus } : t,
          ),
        };
      });
      return { previous };
    },
    onError: (_err, variables, context) => {
      if (context?.previous) {
        queryClient.setQueryData(ticketsQueryKey, context.previous);
      }
      toast.error(`Cannot move to "${variables.status}"`);
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ticketsQueryKey });
    },
  });

  const handleDragStart = (event: DragStartEvent) => {
    const ticket = tickets.find((t) => t.ticket_id === event.active.id);
    setActiveTicket(ticket ?? null);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    setActiveTicket(null);
    const { active, over } = event;
    if (!over) return;

    const ticketId = active.id as string;
    const newStatus = over.id as string;

    const ticket = tickets.find((t) => t.ticket_id === ticketId);
    if (!ticket || ticket.status === newStatus) return;

    // Client-side transition guard (TKB-012) blocks obviously invalid drops.
    const validTransitions = VALID_TRANSITIONS[ticket.status] ?? [];
    if (!validTransitions.includes(newStatus)) {
      toast.error(`Cannot move from "${ticket.status}" to "${newStatus}"`);
      return;
    }

    updateStatusMut.mutate({ ticketId, status: newStatus });
  };

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
    >
      <div className="flex gap-4 overflow-x-auto pb-4" data-testid="ticket-kanban-board">
        {columns.map((col) => {
          const columnTickets = tickets.filter((t) => t.status === col.status_key);
          return <KanbanColumn key={col.column_id} column={col} tickets={columnTickets} />;
        })}
        {!columns.length && (
          <p className="text-sm text-muted-foreground">This board has no columns configured.</p>
        )}
      </div>

      <DragOverlay>
        {activeTicket && (
          <div className="bg-card rounded-lg border p-3 shadow-lg opacity-80 w-72">
            <CardBody ticket={activeTicket} />
          </div>
        )}
      </DragOverlay>
    </DndContext>
  );
}
