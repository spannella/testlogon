import {
  FileText,
  FileImage,
  FileAudio,
  FileVideo,
  File,
  Download,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface FileMessageCardProps {
  fileName?: string;
  fileUrl?: string;
  kind: string;
  isOwn: boolean;
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

export function FileMessageCard({ fileName, fileUrl, kind, isOwn }: FileMessageCardProps) {
  const ext = extensionFromName(fileName);

  return (
    <a
      href={fileUrl ?? "#"}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        "mt-1 flex items-center gap-3 rounded-lg border px-3 py-2 transition-colors",
        isOwn
          ? "border-primary-foreground/20 hover:bg-primary-foreground/10"
          : "border-border hover:bg-accent",
      )}
    >
      <div
        className={cn(
          "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
          isOwn ? "bg-primary-foreground/15 text-primary-foreground" : "bg-muted text-muted-foreground",
        )}
      >
        {fileIcon(kind)}
      </div>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{fileName ?? "File"}</p>
        {ext && (
          <p
            className={cn(
              "text-xs",
              isOwn ? "text-primary-foreground/60" : "text-muted-foreground",
            )}
          >
            {ext} file
          </p>
        )}
      </div>
      <Download
        className={cn(
          "h-4 w-4 shrink-0",
          isOwn ? "text-primary-foreground/60" : "text-muted-foreground",
        )}
      />
    </a>
  );
}
