import { useState, useEffect, useCallback } from "react";
import { Download, X, ChevronLeft, ChevronRight, FileText, FileImage, FileAudio, FileVideo, File } from "lucide-react";
import { Button } from "@/components/ui/button";
import { previewUrl, downloadUrl } from "@/api/endpoints/files";
import type { FileEntry } from "@/api/types";

function fileIcon(ct?: string) {
  if (!ct) return <File className="h-5 w-5" />;
  if (ct.startsWith("image/")) return <FileImage className="h-5 w-5" />;
  if (ct.startsWith("audio/")) return <FileAudio className="h-5 w-5" />;
  if (ct.startsWith("video/")) return <FileVideo className="h-5 w-5" />;
  if (ct === "application/pdf" || ct.startsWith("text/")) return <FileText className="h-5 w-5" />;
  return <File className="h-5 w-5" />;
}

function formatBytes(bytes?: number): string {
  if (bytes == null) return "";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + (sizes[i] ?? "TB");
}

interface FilePreviewProps {
  file: FileEntry;
  files: FileEntry[];
  onClose: () => void;
  onNavigate: (file: FileEntry) => void;
}

export function FilePreview({ file, files, onClose, onNavigate }: FilePreviewProps) {
  const ct = file.content_type ?? "";
  const url = previewUrl(file.path);

  // Find index for prev/next
  const filesList = files.filter((f) => f.type === "file");
  const currentIdx = filesList.findIndex((f) => f.path === file.path);
  const prevFile = currentIdx > 0 ? filesList[currentIdx - 1] : undefined;
  const nextFile = currentIdx < filesList.length - 1 ? filesList[currentIdx + 1] : undefined;

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowLeft" && prevFile) onNavigate(prevFile);
      if (e.key === "ArrowRight" && nextFile) onNavigate(nextFile);
    },
    [onClose, onNavigate, prevFile, nextFile],
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-background/95 backdrop-blur-sm">
      {/* Header */}
      <div className="flex items-center gap-3 border-b px-4 py-3">
        <div className="text-muted-foreground">{fileIcon(ct)}</div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{file.name}</p>
          <p className="text-xs text-muted-foreground">
            {ct || "Unknown type"}
            {file.size != null && <span className="ml-2">{formatBytes(file.size)}</span>}
          </p>
        </div>
        <Button variant="outline" size="sm" asChild>
          <a href={downloadUrl(file.path)} download>
            <Download className="mr-1 h-3.5 w-3.5" />
            Download
          </a>
        </Button>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <div className="relative flex-1 overflow-auto">
        {/* Nav arrows */}
        {prevFile && (
          <button
            className="absolute left-2 top-1/2 z-10 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full bg-muted/80 transition-colors hover:bg-muted"
            onClick={() => onNavigate(prevFile)}
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
        )}
        {nextFile && (
          <button
            className="absolute right-2 top-1/2 z-10 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full bg-muted/80 transition-colors hover:bg-muted"
            onClick={() => onNavigate(nextFile)}
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        )}

        <div className="flex h-full items-center justify-center p-8">
          {ct.startsWith("image/") ? (
            <img
              src={url}
              alt={file.name}
              className="max-h-full max-w-full rounded-lg object-contain"
            />
          ) : ct === "application/pdf" ? (
            <iframe
              src={url}
              title={file.name}
              className="h-full w-full max-w-4xl rounded-lg border"
            />
          ) : ct.startsWith("text/") || ct === "application/json" || ct === "application/xml" ? (
            <TextPreview url={url} />
          ) : (
            <div className="flex flex-col items-center gap-4 text-center">
              {fileIcon(ct)}
              <p className="text-sm text-muted-foreground">
                Preview not available for this file type
              </p>
              <Button variant="outline" size="sm" asChild>
                <a href={downloadUrl(file.path)} download>
                  <Download className="mr-1 h-3.5 w-3.5" /> Download to view
                </a>
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Footer — file index */}
      {filesList.length > 1 && (
        <div className="border-t px-4 py-2 text-center text-xs text-muted-foreground">
          {currentIdx + 1} of {filesList.length} files
        </div>
      )}
    </div>
  );
}

// ── Text file preview (fetches content) ─────────────────────────

function TextPreview({ url }: { url: string }) {
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error("fetch failed");
        return r.text();
      })
      .then((text) => {
        if (!cancelled) setContent(text);
      })
      .catch(() => {
        if (!cancelled) setError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [url]);

  if (error) {
    return <p className="text-sm text-muted-foreground">Failed to load preview</p>;
  }

  if (content === null) {
    return <p className="text-sm text-muted-foreground animate-pulse">Loading preview...</p>;
  }

  return (
    <pre className="max-h-full w-full max-w-4xl overflow-auto rounded-lg border bg-muted/50 p-4 text-xs leading-relaxed">
      {content}
    </pre>
  );
}
