import * as React from "react";
import { AlertTriangle, ChevronDown, ChevronRight, RotateCcw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useOfflineStore, type DeadLetterItem } from "@/stores/offlineStore";

function formatAge(enqueuedAt: number): string {
  const seconds = Math.floor((Date.now() - enqueuedAt) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function previewText(item: DeadLetterItem): string {
  if (item.type === "send_message") {
    const req = (item.payload as { req?: { text?: string } })?.req;
    return req?.text ? req.text.slice(0, 60) : "Message";
  }
  if (item.type === "create_post") {
    const payload = item.payload as { body?: string };
    return payload?.body ? payload.body.slice(0, 60) : "Post";
  }
  return "Unknown";
}

function typeLabel(type: string): string {
  if (type === "send_message") return "Message";
  if (type === "create_post") return "Post";
  return type;
}

export function DeadLetterPanel() {
  const deadLetter = useOfflineStore((s) => s.deadLetter);
  const retryDeadLetter = useOfflineStore((s) => s.retryDeadLetter);
  const discardDeadLetter = useOfflineStore((s) => s.discardDeadLetter);
  const [open, setOpen] = React.useState(true);

  if (deadLetter.length === 0) return null;

  return (
    <div
      data-testid="dead-letter-panel"
      className="border-b border-destructive/30 bg-destructive/5 px-4 py-2"
    >
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 text-sm font-medium text-destructive"
        aria-expanded={open}
      >
        <AlertTriangle className="h-4 w-4" />
        <span>
          {deadLetter.length} failed item{deadLetter.length !== 1 ? "s" : ""}
        </span>
        {open ? (
          <ChevronDown className="ml-auto h-4 w-4" />
        ) : (
          <ChevronRight className="ml-auto h-4 w-4" />
        )}
      </button>

      {open && (
        <div className="mt-2 space-y-2">
          {deadLetter.map((item) => (
            <Card key={item.id} className="border-destructive/20">
              <CardContent className="flex items-start gap-3 p-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="font-semibold">{typeLabel(item.type)}</span>
                    <span>&middot;</span>
                    <span>{item.retryCount} retries</span>
                    <span>&middot;</span>
                    <span>{formatAge(item.enqueuedAt)}</span>
                  </div>
                  <p className="mt-0.5 truncate text-sm">{previewText(item)}</p>
                  {item.lastError && (
                    <p className="mt-0.5 truncate text-xs text-destructive">
                      {item.lastError}
                    </p>
                  )}
                </div>
                <div className="flex shrink-0 gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => retryDeadLetter(item.id)}
                    title="Retry"
                    data-testid={`retry-${item.id}`}
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => discardDeadLetter(item.id)}
                    title="Discard"
                    data-testid={`discard-${item.id}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
