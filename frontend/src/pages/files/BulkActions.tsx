import { useState } from "react";
import { Archive, Trash2, FolderInput, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { downloadZip, deleteFile, deleteFolder } from "@/api/endpoints/files";
import type { FileEntry } from "@/api/types";

interface BulkActionsProps {
  selectedKeys: Set<string>;
  items: FileEntry[];
  onClearSelection: () => void;
  onMoveSelected: () => void;
  onDeleted: () => void;
}

export function BulkActions({
  selectedKeys,
  items,
  onClearSelection,
  onMoveSelected,
  onDeleted,
}: BulkActionsProps) {
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [zipping, setZipping] = useState(false);

  const count = selectedKeys.size;
  if (count === 0) return null;

  const selectedItems = items.filter((f) => selectedKeys.has(f.path));
  const selectedPaths = selectedItems.map((f) => f.path);

  const handleDownloadZip = async () => {
    setZipping(true);
    try {
      await downloadZip(selectedPaths);
      toast.success("ZIP download started");
    } catch {
      toast.error("Failed to download ZIP");
    } finally {
      setZipping(false);
    }
  };

  const handleBulkDelete = async () => {
    setDeleting(true);
    let errors = 0;
    for (const entry of selectedItems) {
      try {
        if (entry.type === "folder") {
          await deleteFolder(entry.path);
        } else {
          await deleteFile(entry.path);
        }
      } catch {
        errors++;
      }
    }
    setDeleting(false);
    setDeleteOpen(false);
    onClearSelection();
    onDeleted();
    if (errors > 0) {
      toast.error(`Failed to delete ${errors} item(s)`);
    } else {
      toast.success(`Deleted ${count} item(s)`);
    }
  };

  return (
    <>
      <div className="flex items-center gap-2 rounded-lg border bg-muted/50 px-3 py-2">
        <span className="text-sm font-medium">
          {count} item{count !== 1 ? "s" : ""} selected
        </span>

        <div className="ml-2 flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownloadZip}
            disabled={zipping}
          >
            <Archive className="mr-1 h-3.5 w-3.5" />
            {zipping ? "Zipping..." : "Download ZIP"}
          </Button>

          <Button variant="outline" size="sm" onClick={onMoveSelected}>
            <FolderInput className="mr-1 h-3.5 w-3.5" />
            Move to...
          </Button>

          <Button
            variant="destructive"
            size="sm"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-1 h-3.5 w-3.5" />
            Delete
          </Button>
        </div>

        <Button
          variant="ghost"
          size="icon"
          className="ml-auto h-7 w-7"
          onClick={onClearSelection}
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete selected items?"
        description={`This will permanently delete ${count} item${count !== 1 ? "s" : ""}. This cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleBulkDelete}
        loading={deleting}
      />
    </>
  );
}
