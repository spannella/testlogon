import * as React from "react";
import { Upload } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { uploadFile } from "@/api/endpoints/files";

interface UploadZoneProps {
  currentPath: string;
  onUploadComplete: () => void;
  children: React.ReactNode;
}

export function UploadZone({ currentPath, onUploadComplete, children }: UploadZoneProps) {
  const [dragOver, setDragOver] = React.useState(false);
  const dragCountRef = React.useRef(0);

  const handleFiles = async (files: FileList | File[]) => {
    const fileArray = Array.from(files);
    for (const file of fileArray) {
      const targetPath = currentPath.endsWith("/")
        ? currentPath + file.name
        : currentPath + "/" + file.name;

      const toastId = toast.loading(`Uploading ${file.name}...`);
      try {
        await uploadFile(file, targetPath);
        toast.success(`Uploaded ${file.name}`, { id: toastId });
      } catch {
        toast.error(`Failed to upload ${file.name}`, { id: toastId });
      }
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
    dragCountRef.current--;
    if (dragCountRef.current === 0) setDragOver(false);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    dragCountRef.current = 0;
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) {
      handleFiles(e.dataTransfer.files);
    }
  };

  return (
    <div
      className="relative"
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
