import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Folder, ChevronRight, ChevronDown, FolderInput, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { listFiles } from "@/api/endpoints/files";

interface MoveDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentFolder: string;
  onMove: (targetFolder: string) => void;
  loading?: boolean;
}

export function MoveDialog({ open, onOpenChange, currentFolder, onMove, loading }: MoveDialogProps) {
  const [selected, setSelected] = useState("/");

  const isSameFolder = selected === currentFolder || selected + "/" === currentFolder;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderInput className="h-4 w-4" /> Move to folder
          </DialogTitle>
        </DialogHeader>

        <div className="max-h-72 overflow-auto rounded-lg border p-2">
          <FolderNode
            path="/"
            name="Root"
            depth={0}
            selectedPath={selected}
            onSelect={setSelected}
            defaultOpen
          />
        </div>

        <p className="text-xs text-muted-foreground">
          Target: <span className="font-mono">{selected}</span>
        </p>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => onMove(selected)}
            disabled={isSameFolder || loading}
          >
            {loading ? (
              <>
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                Moving...
              </>
            ) : (
              "Move here"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Recursive folder tree node ─────────────────────────────────

interface FolderNodeProps {
  path: string;
  name: string;
  depth: number;
  selectedPath: string;
  onSelect: (path: string) => void;
  defaultOpen?: boolean;
}

function FolderNode({ path, name, depth, selectedPath, onSelect, defaultOpen }: FolderNodeProps) {
  const [expanded, setExpanded] = useState(!!defaultOpen);

  const foldersQuery = useQuery({
    queryKey: ["files-folders", path],
    queryFn: () => listFiles(path, { sort_by: "name", sort_dir: "asc" }),
    enabled: expanded,
  });

  const subfolders = (foldersQuery.data?.items ?? []).filter((f) => f.type === "folder");
  const isSelected = selectedPath === path;

  return (
    <div>
      <button
        className={cn(
          "flex w-full items-center gap-1 rounded px-2 py-1 text-sm transition-colors hover:bg-accent",
          isSelected && "bg-primary/10 font-medium text-primary",
        )}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => onSelect(path)}
      >
        <button
          className="shrink-0 p-0.5"
          onClick={(e) => {
            e.stopPropagation();
            setExpanded((o) => !o);
          }}
        >
          {expanded ? (
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
          )}
        </button>
        <Folder className="h-4 w-4 shrink-0 text-primary" />
        <span className="truncate">{name}</span>
      </button>

      {expanded && (
        <div>
          {foldersQuery.isLoading && (
            <div
              className="flex items-center gap-2 px-2 py-1 text-xs text-muted-foreground"
              style={{ paddingLeft: `${(depth + 1) * 16 + 8}px` }}
            >
              <Loader2 className="h-3 w-3 animate-spin" />
              Loading...
            </div>
          )}
          {subfolders.map((folder) => (
            <FolderNode
              key={folder.path}
              path={folder.path}
              name={folder.name}
              depth={depth + 1}
              selectedPath={selectedPath}
              onSelect={onSelect}
            />
          ))}
          {!foldersQuery.isLoading && subfolders.length === 0 && (
            <p
              className="px-2 py-1 text-xs italic text-muted-foreground"
              style={{ paddingLeft: `${(depth + 1) * 16 + 8}px` }}
            >
              No subfolders
            </p>
          )}
        </div>
      )}
    </div>
  );
}
