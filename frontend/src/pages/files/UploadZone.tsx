import * as React from "react";
import { Upload } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { uploadFile } from "@/api/endpoints/files";

const MAX_CONCURRENT_UPLOADS = 3;
const MAX_FILES_PER_DROP = 20;
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB

interface UploadZoneProps {
  currentPath: string;
  onUploadComplete: () => void;
  children: React.ReactNode;
}

export function UploadZone({ currentPath, onUploadComplete, children }: UploadZoneProps) {
  const [dragOver, setDragOver] = React.useState(false);
  const dragCountRef = React.useRef(0);

  const handleFiles = async (files: FileList | File[]) => {
    const fileArray = Array.from(files).slice(0, MAX_FILES_PER_DROP);

    if (Array.from(files).length > MAX_FILES_PER_DROP) {
      toast.warning(`Only the first ${MAX_FILES_PER_DROP} files will be uploaded`);
    }

    // Validate sizes
    const oversized = fileArray.filter((f) => f.size > MAX_UPLOAD_SIZE);
    const valid = fileArray.filter((f) => f.size <= MAX_UPLOAD_SIZE);

    if (oversized.length > 0) {
      toast.error(`${oversized.length} file(s) exceed the 100MB limit and were skipped`);
    }
    if (valid.length === 0) return;

    // Show consolidated progress toast
    const progressToastId = toast.loading(`Uploading ${valid.length} file(s)...`);
    let completed = 0;
    let failed = 0;

    // Upload with concurrency limit
    const queue = [...valid];
    const inFlight: Promise<void>[] = [];

    const uploadOne = async (file: File) => {
      const targetPath = currentPath.endsWith("/")
        ? currentPath + file.name
        : currentPath + "/" + file.name;
      try {
        await uploadFile(file, targetPath);
        completed++;
      } catch {
        failed++;
      }
      toast.loading(
        `Uploading: ${completed + failed}/${valid.length}${failed > 0 ? ` (${failed} failed)` : ""}`,
        { id: progressToastId },
      );
    };

    while (queue.length > 0) {
      while (inFlight.length < MAX_CONCURRENT_UPLOADS && queue.length > 0) {
        const file = queue.shift()!;
        const p = uploadOne(file).then(() => {
          const idx = inFlight.indexOf(p);
          if (idx >= 0) inFlight.splice(idx, 1);
        });
        inFlight.push(p);
      }
      if (inFlight.length > 0) {
        await Promise.race(inFlight);
      }
    }

    // Wait for remaining
    await Promise.allSettled(inFlight);

    if (failed === 0) {
      toast.success(`Uploaded ${completed} file(s)`, { id: progressToastId });
    } else {
      toast.warning(`Uploaded ${completed}/${valid.length} (${failed} failed)`, { id: progressToastId });
    }

    onUploadComplete();
  };

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    dragCountRef.current++;
    if (dragCountRef.current === 1) setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    dragCountRef.current = Math.max(0, dragCountRef.current - 1);
    if (dragCountRef.current === 0) setDragOver(false);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCountRef.current = 0;
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) {
      handleFiles(e.dataTransfer.files);
    }
  };

  // Listen for global app-file-drop events for the files page
  React.useEffect(() => {
    const handler = (e: Event) => {
      const custom = e as CustomEvent<{ files: File[]; context: string }>;
      if (custom.detail.context !== "files") return;
      handleFiles(custom.detail.files);
    };
    window.addEventListener("app-file-drop", handler);
    return () => window.removeEventListener("app-file-drop", handler);
  }, [currentPath]);

  return (
    <div
      className="relative"
      data-testid="upload-zone"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {children}

      {/* Drag overlay */}
      {dragOver && (
        <div className={cn(
          "absolute inset-0 z-30 flex items-center justify-center",
          "rounded-lg border-2 border-dashed border-primary bg-primary/5 backdrop-blur-sm",
        )}>
          <div className="flex flex-col items-center gap-2 text-primary">
            <Upload className="h-10 w-10" />
            <p className="text-sm font-medium">Drop files here to upload</p>
          </div>
        </div>
      )}
    </div>
  );
}
