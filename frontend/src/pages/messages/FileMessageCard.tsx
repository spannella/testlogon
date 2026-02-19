import {
  FileText,
  FileImage,
  FileAudio,
  FileVideo,
  File,
  Download,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface FileMessageCardProps {
  fileName?: string;
  fileUrl?: string;
  kind: string;
  isOwn: boolean;
  consumptionState?: "pending" | "consumed" | "expired" | "failed";
  onceError?: string | null;
  onOpen?: () => void;
  opening?: boolean;
}

function fileIcon(kind: string) {
  switch (kind) {
    case "image":
      return <FileImage className="h-5 w-5" />;
    case "audio":
      return <FileAudio className="h-5 w-5" />;
    case "video":
      return <FileVideo className="h-5 w-5" />;
    case "file":
      return <FileText className="h-5 w-5" />;
    default:
      return <File className="h-5 w-5" />;
  }
}

function extensionFromName(name?: string): string {
  if (!name) return "";
  const parts = name.split(".");
  return parts.length > 1 ? (parts[parts.length - 1] ?? "").toUpperCase() : "";
}

export function FileMessageCard({
  fileName,
  fileUrl,
  kind,
  isOwn,
  consumptionState,
  onceError,
  onOpen,
  opening,
}: FileMessageCardProps) {
  const ext = extensionFromName(fileName);
  const isConsumed = consumptionState === "consumed";
  const disabled = isConsumed || !fileUrl || opening;

  return (
    <div className="mt-1">

      <button
        type="button"
        onClick={() => onOpen?.()}
        disabled={disabled}
        className={cn(
          "w-full text-left mt-1 flex items-center gap-3 rounded-lg border px-3 py-2 transition-colors",
          isOwn
            ? "border-primary-foreground/20 hover:bg-primary-foreground/10"
            : "border-border hover:bg-accent",
          disabled && "opacity-60 cursor-not-allowed",
        )}
      >
        <div
          className={cn(
            "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
            isOwn ? "bg-primary-foreground/15 text-primary-foreground" : "bg-muted text-muted-foreground",
          )}
        >
          {opening ? <Loader2 className="h-5 w-5 animate-spin" /> : fileIcon(kind)}
        </div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{fileName ?? "File"}</p>
          {isConsumed ? (
            <p className={cn("text-xs", isOwn ? "text-primary-foreground/60" : "text-muted-foreground")}>Consumed</p>
          ) : ext ? (
            <p
              className={cn(
                "text-xs",
                isOwn ? "text-primary-foreground/60" : "text-muted-foreground",
              )}
            >
              {ext} file
            </p>
          ) : null}
        </div>
        <Download
          className={cn(
            "h-4 w-4 shrink-0",
            isOwn ? "text-primary-foreground/60" : "text-muted-foreground",
          )}
        />
      </button>

      {onceError && <p className="mt-1 text-xs text-red-600">{onceError}</p>}
    </div>
  );
}
