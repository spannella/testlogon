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
import { setTicketStatus, type Ticket, type TicketStatus } from "@/api/endpoints/tickets";
import { useState } from "react";
import { UserProfileLink } from "@/components/shared/UserProfileLink";

// ─── Status transition rules (must match backend _STATUS_TRANSITIONS) ──

const VALID_TRANSITIONS: Record<string, string[]> = {
  open: ["in_progress", "done"],
  in_progress: ["waiting_on_user", "done", "open"],
  waiting_on_user: ["in_progress", "done", "open"],
  done: ["open"],
};

const KANBAN_COLUMNS = [
  { id: "open" as const, label: "Open", color: "bg-blue-500" },
  { id: "in_progress" as const, label: "In Progress", color: "bg-purple-500" },
  { id: "waiting_on_user" as const, label: "Waiting on User", color: "bg-yellow-500" },
  { id: "done" as const, label: "Done", color: "bg-green-500" },
] as const;

function statusToWritable(status: string): "done" | "reopened" | TicketStatus {
  if (status === "open") return "reopened"; // "done" -> "open" requires "reopened" command
  return status as TicketStatus;
}

// ─── DraggableTicketCard ──────────────────────────────────────────

function DraggableTicketCard({ ticket }: { ticket: Ticket }) {
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
      <p className="text-sm font-medium truncate">{ticket.subject}</p>
      <div className="flex items-center gap-2 mt-2">
        <Badge variant="outline" className="text-[10px]">{ticket.status}</Badge>
        {ticket.assigned_admin_sub && (
          <span className="text-[10px] text-muted-foreground truncate">
            Assigned:{" "}
            <UserProfileLink
              userId={ticket.assigned_admin_sub}
              displayName={ticket.assigned_admin_sub.slice(0, 8) + "..."}
              className="hover:underline"
              ariaLabel={`Open ${ticket.assigned_admin_sub} profile`}
            />
          </span>
        )}
      </div>
    </div>
  );
}

// ─── KanbanColumn ─────────────────────────────────────────────────

function KanbanColumn({
  column,
  tickets,
}: {
  column: (typeof KANBAN_COLUMNS)[number];
  tickets: Ticket[];
}) {
  const { setNodeRef, isOver } = useDroppable({ id: column.id });

  return (
    <div
      ref={setNodeRef}
      data-testid={`kanban-column-${column.id}`}
      className={cn(
        "w-72 shrink-0 rounded-lg bg-muted/50 p-3",
        isOver && "ring-2 ring-primary bg-primary/5",
      )}
    >
      <div className="flex items-center gap-2 mb-3">
        <div className={cn("w-3 h-3 rounded-full", column.color)} />
        <h3 className="text-sm font-semibold">{column.label}</h3>
        <Badge variant="outline" className="ml-auto" data-testid={`kanban-count-${column.id}`}>
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

// ─── TicketKanbanBoard ────────────────────────────────────────────

interface TicketKanbanBoardProps {
  tickets: Ticket[];
  isAdmin: boolean;
}

export function TicketKanbanBoard({ tickets, isAdmin: _isAdmin }: TicketKanbanBoardProps) {
  void _isAdmin; // reserved for future admin-only features
  const queryClient = useQueryClient();
  const [activeTicket, setActiveTicket] = useState<Ticket | null>(null);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor),
  );

  const updateStatusMut = useMutation({
    mutationFn: ({ ticketId, status }: { ticketId: string; status: string }) => {
      const writable = statusToWritable(status);
      return setTicketStatus(ticketId, writable);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tickets"] });
    },
    onError: (_err, variables) => {
      toast.error(`Cannot change status to ${variables.status}`);
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

    // Check valid transition client-side
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
        {KANBAN_COLUMNS.map((col) => {
          const columnTickets = tickets.filter((t) => t.status === col.id);
          return (
            <KanbanColumn key={col.id} column={col} tickets={columnTickets} />
          );
        })}
      </div>

      <DragOverlay>
        {activeTicket && (
          <div className="bg-card rounded-lg border p-3 shadow-lg opacity-80 w-72">
            <p className="text-sm font-medium truncate">{activeTicket.subject}</p>
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="outline" className="text-[10px]">{activeTicket.status}</Badge>
            </div>
          </div>
        )}
      </DragOverlay>
    </DndContext>
  );
}
