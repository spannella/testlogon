import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { useLocation } from "react-router-dom";
import { Upload, MessageSquare, FolderOpen, FileText, ImageIcon } from "lucide-react";
import { toast } from "sonner";

const MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_UPLOAD_SIZE_MB = 100;
const MAX_FILES_PER_DROP = 20;

interface DropContext {
  type: "message" | "files" | "feed" | "broadcast" | "default";
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

function getDropContext(pathname: string): DropContext {
  if (pathname.startsWith("/messages")) {
    return { type: "message", label: "Drop to attach to message", icon: MessageSquare };
  }
  if (pathname.startsWith("/files")) {
    return { type: "files", label: "Drop to upload to current folder", icon: FolderOpen };
  }
  if (pathname.startsWith("/feed")) {
    return { type: "feed", label: "Drop to attach to post", icon: FileText };
  }
  if (pathname.startsWith("/broadcast")) {
    return { type: "broadcast", label: "Drop to add overlay", icon: ImageIcon };
  }
  return { type: "default", label: "Drop to upload to Files", icon: Upload };
}

function DropOverlay({ context }: { context: DropContext }) {
  const Icon = context.icon;
  return (
    <div
      data-testid="app-drop-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
    >
      <div className="flex flex-col items-center gap-4 rounded-xl border-2 border-dashed border-primary bg-primary/5 p-12">
        <Icon className="h-16 w-16 text-primary" />
        <p className="text-lg font-semibold text-primary">{context.label}</p>
        <p className="text-sm text-muted-foreground">Release to drop</p>
      </div>
    </div>
  );
}

export function AppDropZone({ children }: { children: React.ReactNode }) {
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const location = useLocation();
  const dragCount = useRef(0);

  const dropContext = useMemo(() => getDropContext(location.pathname), [location.pathname]);

  const handleDragEnter = useCallback((e: DragEvent) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    dragCount.current++;
    if (dragCount.current === 1) setIsDraggingFile(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    dragCount.current = Math.max(0, dragCount.current - 1);
    if (dragCount.current === 0) setIsDraggingFile(false);
  }, []);

  const handleDragOver = useCallback((e: DragEvent) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  }, []);

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    dragCount.current = 0;
    setIsDraggingFile(false);

    const files = Array.from(e.dataTransfer?.files ?? []);
    if (files.length === 0) return;

    // Validate file count
    if (files.length > MAX_FILES_PER_DROP) {
      toast.error(`Maximum ${MAX_FILES_PER_DROP} files per drop`);
      return;
    }

    // Validate file sizes
    const oversized = files.filter((f) => f.size > MAX_UPLOAD_SIZE);
    if (oversized.length > 0) {
      toast.error(`${oversized.length} file(s) exceed the ${MAX_UPLOAD_SIZE_MB}MB limit`);
    }
    const validFiles = files.filter((f) => f.size <= MAX_UPLOAD_SIZE);
    if (validFiles.length === 0) return;

    // Route to page-specific handler via custom event
    const event = new CustomEvent("app-file-drop", {
      detail: { files: validFiles, context: dropContext.type },
    });
    window.dispatchEvent(event);
  }, [dropContext]);

  useEffect(() => {
    const el = document.documentElement;
    el.addEventListener("dragenter", handleDragEnter);
    el.addEventListener("dragleave", handleDragLeave);
    el.addEventListener("dragover", handleDragOver);
    el.addEventListener("drop", handleDrop);
    return () => {
      el.removeEventListener("dragenter", handleDragEnter);
      el.removeEventListener("dragleave", handleDragLeave);
      el.removeEventListener("dragover", handleDragOver);
      el.removeEventListener("drop", handleDrop);
    };
  }, [handleDragEnter, handleDragLeave, handleDragOver, handleDrop]);

  return (
    <div data-testid="app-drop-zone" className="contents">
      {children}
      {isDraggingFile && <DropOverlay context={dropContext} />}
    </div>
  );
}
