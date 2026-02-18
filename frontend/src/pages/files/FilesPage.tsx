import * as React from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Upload,
  FolderPlus,
  Search,
  FolderOpen,
  ChevronRight,
  Archive,
  ChevronDown,
  Lock,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import type { SortState } from "@/components/shared/DataTable";
import type { FileEntry, SharedItem } from "@/api/types";
import { encryptFileChunked, decryptFileChunked, type EncryptionMetadata } from "@/lib/fileEncryption";
import { evaluateEncryptionPassword } from "@/lib/encryptionPasswordPolicy";
import {
  buildRememberedFileId,
  canRememberPasswords,
  clearAllRememberedPasswords,
  clearRememberedPassword,
  loadRememberedPassword,
  purgeExpiredRememberedPasswords,
  saveRememberedPassword,
} from "@/lib/filePasswordStore";

import {
  listFiles,
  searchFiles,
  searchText,
  createFolder,
  uploadFile,
  deleteFile,
  deleteFolder,
  renameFile,
  renameFolder,
  moveFile,
  uploadZip,
  fsPresignUpload,
  completeUpload,
  emitFileCryptoTelemetry,
  getSharedFileInfo,
  getUsageSummary,
  sharedPreviewUrl,
} from "@/api/endpoints/files";
import { FileTable } from "./FileTable";
import { FilePreview } from "./FilePreview";
import { SharedWithMe } from "./SharedWithMe";
import { ShareDialog } from "./ShareDialog";
import { UploadZone } from "./UploadZone";
import { BulkActions } from "./BulkActions";
import { MoveDialog } from "./MoveDialog";
import ImpersonationRouteIndicator from "@/components/shared/ImpersonationRouteIndicator";

type SearchMode = "name" | "content";
type PasswordDialogResult = { password: string; remember: boolean };
type PreviewContext = {
  file: FileEntry;
  files: FileEntry[];
  source: "owned" | "shared";
  sharedOwner?: string;
};

const PRESIGN_THRESHOLD = 5 * 1024 * 1024; // 5 MB

function formatBytesCompact(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function warningLevel(percent: number): "none" | "warn" | "critical" {
  if (percent >= 95) return "critical";
  if (percent >= 80) return "warn";
  return "none";
}

export default function FilesPage() {
  const queryClient = useQueryClient();
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const zipInputRef = React.useRef<HTMLInputElement>(null);

  // ── State ───────────────────────────────────────────────────────

  const [currentPath, setCurrentPath] = React.useState("/");
  const [sort, setSort] = React.useState<SortState>({ column: "name", direction: "asc" });
  const [selectedKeys, setSelectedKeys] = React.useState<Set<string>>(new Set());
  const [searchValue, setSearchValue] = React.useState("");
  const [isSearching, setIsSearching] = React.useState(false);
  const [searchMode, setSearchMode] = React.useState<SearchMode>("name");
  const [activeTab, setActiveTab] = React.useState("my-files");
  const [encryptUploads, setEncryptUploads] = React.useState(false);
  const [allowRememberPasswords, setAllowRememberPasswords] = React.useState(
    () => localStorage.getItem("filemgr.rememberPasswordsOptIn") === "1",
  );
  const [passwordDialogOpen, setPasswordDialogOpen] = React.useState(false);
  const [passwordDialogTitle, setPasswordDialogTitle] = React.useState("Enter password");
  const [passwordDialogDescription, setPasswordDialogDescription] = React.useState<string | undefined>(undefined);
  const [passwordValue, setPasswordValue] = React.useState("");
  const [passwordConfirmValue, setPasswordConfirmValue] = React.useState("");
  const [rememberPasswordChoice, setRememberPasswordChoice] = React.useState(false);
  const [allowRememberPasswordChoice, setAllowRememberPasswordChoice] = React.useState(false);
  const [requirePasswordConfirm, setRequirePasswordConfirm] = React.useState(false);
  const passwordResolverRef = React.useRef<((value: PasswordDialogResult | null) => void) | null>(null);

  // Dialog state
  const [newFolderOpen, setNewFolderOpen] = React.useState(false);
  const [newFolderName, setNewFolderName] = React.useState("");
  const [renameTarget, setRenameTarget] = React.useState<FileEntry | null>(null);
  const [renameName, setRenameName] = React.useState("");
  const [shareTarget, setShareTarget] = React.useState<FileEntry | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<FileEntry | null>(null);

  // Preview state
  const [previewContext, setPreviewContext] = React.useState<PreviewContext | null>(null);

  // Move dialog state
  const [moveDialogOpen, setMoveDialogOpen] = React.useState(false);
  const [moveTarget, setMoveTarget] = React.useState<FileEntry | null>(null);

  // ── Queries ─────────────────────────────────────────────────────

  const filesQuery = useQuery({
    queryKey: ["files", currentPath, sort.column, sort.direction],
    queryFn: () => listFiles(currentPath, { sort_by: sort.column, sort_dir: sort.direction }),
    enabled: !isSearching && activeTab === "my-files",
  });

  const nameSearchQuery = useQuery({
    queryKey: ["files-search", searchValue],
    queryFn: () => searchFiles(searchValue),
    enabled: isSearching && searchMode === "name" && searchValue.length > 0,
  });

  const contentSearchQuery = useQuery({
    queryKey: ["files-search-text", searchValue],
    queryFn: () => searchText(searchValue),
    enabled: isSearching && searchMode === "content" && searchValue.length > 0,
  });

  const usageSummaryQuery = useQuery({
    queryKey: ["files-usage-summary"],
    queryFn: () => getUsageSummary(),
  });

  const displayItems: FileEntry[] = isSearching
    ? searchMode === "name"
      ? (nameSearchQuery.data?.results ?? [])
      : (contentSearchQuery.data?.results ?? [])
    : (filesQuery.data?.items ?? []);

  const isLoading = isSearching
    ? searchMode === "name"
      ? nameSearchQuery.isLoading
      : contentSearchQuery.isLoading
    : filesQuery.isLoading;

  // ── Mutations ───────────────────────────────────────────────────

  const createFolderMut = useMutation({
    mutationFn: (name: string) => {
      const folderPath = currentPath.endsWith("/")
        ? currentPath + name
        : currentPath + "/" + name;
      return createFolder(folderPath);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
      setNewFolderOpen(false);
      setNewFolderName("");
      toast.success("Folder created");
    },
    onError: () => toast.error("Failed to create folder"),
  });

  const deleteMut = useMutation({
    mutationFn: (entry: FileEntry) =>
      entry.type === "folder" ? deleteFolder(entry.path) : deleteFile(entry.path),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
      setDeleteTarget(null);
      setSelectedKeys(new Set());
      toast.success("Deleted successfully");
    },
    onError: () => toast.error("Failed to delete"),
  });

  const renameMut = useMutation({
    mutationFn: ({ entry, newName }: { entry: FileEntry; newName: string }) =>
      entry.type === "folder" ? renameFolder(entry.path, newName) : renameFile(entry.path, newName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
      setRenameTarget(null);
      setRenameName("");
      toast.success("Renamed successfully");
    },
    onError: () => toast.error("Failed to rename"),
  });

  const [moveLoading, setMoveLoading] = React.useState(false);

  // ── Breadcrumbs ─────────────────────────────────────────────────

  const pathSegments = React.useMemo(() => {
    const parts = currentPath.split("/").filter(Boolean);
    const segments: { label: string; path: string }[] = [{ label: "Root", path: "/" }];
    let acc = "";
    for (const part of parts) {
      acc += "/" + part;
      segments.push({ label: part, path: acc });
    }
    return segments;
  }, [currentPath]);

  // ── Search ──────────────────────────────────────────────────────

  const handleSearchChange = (value: string) => {
    setSearchValue(value);
    setIsSearching(value.length > 0);
  };

  const toggleSearchMode = () => {
    setSearchMode((m) => (m === "name" ? "content" : "name"));
  };

  // ── Navigation ──────────────────────────────────────────────────

  const handleNavigate = (folder: FileEntry) => {
    setCurrentPath(folder.path);
    setSelectedKeys(new Set());
    setIsSearching(false);
    setSearchValue("");
  };

  const handleBreadcrumb = (path: string) => {
    setCurrentPath(path);
    setSelectedKeys(new Set());
    setIsSearching(false);
    setSearchValue("");
  };

  // ── Preview ───────────────────────────────────────────────────

  const handlePreview = (file: FileEntry) => {
    setPreviewContext({ file, files: displayItems, source: "owned" });
  };

  const handlePreviewShared = (_item: SharedItem) => {
    const segments = _item.path.split("/").filter(Boolean);
    const name = _item.name || (segments.length > 0 ? (segments[segments.length - 1] ?? _item.path) : _item.path);
    const entry: FileEntry = {
      name,
      path: _item.path,
      type: "file",
      size: _item.size,
      content_type: _item.content_type,
      is_encrypted: _item.is_encrypted,
      enc_metadata: _item.enc_metadata,
      enc_version: _item.enc_version,
      enc_alg: _item.enc_alg,
      enc_kdf: _item.enc_kdf,
      enc_kdf_iterations: _item.enc_kdf_iterations,
      enc_salt_b64: _item.enc_salt_b64,
      enc_iv_b64: _item.enc_iv_b64,
      enc_orig_name: _item.enc_orig_name,
      enc_orig_size: _item.enc_orig_size,
      enc_orig_content_type: _item.enc_orig_content_type,
      preview_kind: _item.preview_kind,
      preview_supported: _item.preview_supported,
      preview_reason: _item.preview_reason,
    };
    setPreviewContext({ file: entry, files: [entry], source: "shared", sharedOwner: _item.owner });
  };

  const requestPassword = React.useCallback((opts: {
    title: string;
    description?: string;
    confirm?: boolean;
    allowRememberChoice?: boolean;
  }) => {
    setPasswordDialogTitle(opts.title);
    setPasswordDialogDescription(opts.description);
    setRequirePasswordConfirm(!!opts.confirm);
    setAllowRememberPasswordChoice(!!opts.allowRememberChoice);
    setRememberPasswordChoice(false);
    setPasswordValue("");
    setPasswordConfirmValue("");
    setPasswordDialogOpen(true);
    return new Promise<PasswordDialogResult | null>((resolve) => {
      passwordResolverRef.current = resolve;
    });
  }, []);

  const completePasswordDialog = (value: PasswordDialogResult | null) => {
    setPasswordDialogOpen(false);
    const resolver = passwordResolverRef.current;
    passwordResolverRef.current = null;
    resolver?.(value);
  };

  const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const resolveEncryptionMetadata = (file: Pick<FileEntry, "enc_metadata" | "enc_version" | "enc_alg" | "enc_kdf" | "enc_kdf_iterations" | "enc_salt_b64" | "enc_iv_b64" | "enc_orig_name" | "enc_orig_size" | "enc_orig_content_type">): EncryptionMetadata | undefined => {
    const raw = file.enc_metadata;
    if (
      raw &&
      typeof raw.version === "number" &&
      typeof raw.alg === "string" &&
      typeof raw.kdf === "string" &&
      typeof raw.iterations === "number" &&
      typeof raw.salt_b64 === "string" &&
      typeof raw.iv_b64 === "string" &&
      typeof raw.orig_name === "string" &&
      typeof raw.orig_size === "number" &&
      typeof raw.mime === "string"
    ) {
      return raw as EncryptionMetadata;
    }

    if (
      typeof file.enc_version !== "number" ||
      typeof file.enc_alg !== "string" ||
      typeof file.enc_kdf !== "string" ||
      typeof file.enc_kdf_iterations !== "number" ||
      typeof file.enc_salt_b64 !== "string" ||
      typeof file.enc_iv_b64 !== "string" ||
      typeof file.enc_orig_name !== "string" ||
      typeof file.enc_orig_size !== "number" ||
      typeof file.enc_orig_content_type !== "string"
    ) {
      return undefined;
    }

    return {
      version: file.enc_version,
      alg: file.enc_alg,
      kdf: file.enc_kdf,
      iterations: file.enc_kdf_iterations,
      salt_b64: file.enc_salt_b64,
      iv_b64: file.enc_iv_b64,
      orig_name: file.enc_orig_name,
      orig_size: file.enc_orig_size,
      mime: file.enc_orig_content_type,
    };
  };

  const performDownload = React.useCallback(async (file: FileEntry, downloadUrl: string) => {
    const toastId = toast.loading(`Preparing ${file.name}...`);
    const encMeta = resolveEncryptionMetadata(file);
    try {
      const resp = await fetch(downloadUrl, { credentials: "include" });
      if (!resp.ok) throw new Error("download failed");
      const blob = await resp.blob();
      if (!file.is_encrypted) {
        triggerDownload(blob, file.name);
        toast.success(`Downloaded ${file.name}`, { id: toastId });
        return;
      }

      const rememberSupported = allowRememberPasswords && canRememberPasswords();
      const fileId = await buildRememberedFileId(file.path, encMeta);
      if (rememberSupported) {
        const remembered = await loadRememberedPassword(fileId);
        if (remembered) {
          try {
            const autoDecrypted = await decryptFileChunked(blob, remembered, encMeta, { useWorker: true });
            const outputName = encMeta?.orig_name || file.name;
            triggerDownload(autoDecrypted, outputName);
            void emitFileCryptoTelemetry({
              event: "remembered_password_used",
              path: file.path,
              remembered_password_used: true,
            });
            toast.success(`Decrypted and downloaded ${outputName}`, { id: toastId });
            return;
          } catch {
            await clearRememberedPassword(fileId);
          }
        }
      }

      const passwordResult = await requestPassword({
        title: "Enter password to decrypt",
        description: `Decrypt ${file.name} locally before saving.`,
        allowRememberChoice: rememberSupported,
      });
      if (!passwordResult?.password) {
        toast.dismiss(toastId);
        return;
      }
      const decrypted = await decryptFileChunked(blob, passwordResult.password, encMeta, {
        useWorker: true,
        onProgress: (p) => toast.loading(`Decrypting ${file.name}... ${p.percent}%`, { id: toastId }),
      });
      if (rememberSupported && passwordResult.remember) {
        await saveRememberedPassword(fileId, passwordResult.password, {
          path: file.path,
          displayName: file.name,
        });
      }
      const outputName = encMeta?.orig_name || file.name;
      triggerDownload(decrypted, outputName);
      toast.success(`Decrypted and downloaded ${outputName}`, { id: toastId });
    } catch {
      if (file.is_encrypted) {
        const hasValidMetadata = !!(
          encMeta?.salt_b64 &&
          encMeta?.iv_b64 &&
          typeof encMeta?.iterations === "number"
        );
        const reason = hasValidMetadata ? "wrong_password" : "corrupted_metadata";
        void emitFileCryptoTelemetry({
          event: "decrypt_failure",
          path: file.path,
          reason,
          remembered_password_used: allowRememberPasswords,
        });
      }
      toast.error(`Failed to download ${file.name}`, { id: toastId });
    }
  }, [allowRememberPasswords, requestPassword]);

  const handleDownload = React.useCallback(async (file: FileEntry) => {
    await performDownload(file, `/v1/fs/download?path=${encodeURIComponent(file.path)}`);
  }, [performDownload]);

  const handleSharedDownload = React.useCallback(async (item: SharedItem) => {
    const info = await getSharedFileInfo(item.owner, item.path);
    const file: FileEntry = {
      ...info,
      name: info.name || item.name || item.path.split("/").filter(Boolean).pop() || item.path,
      path: item.path,
      type: "file",
    };
    await performDownload(
      file,
      `/v1/fs/shared-download?owner=${encodeURIComponent(item.owner)}&path=${encodeURIComponent(item.path)}`,
    );
  }, [performDownload]);

  const handleSharedPreviewDownload = React.useCallback(async (owner: string, file: FileEntry) => {
    const info = await getSharedFileInfo(owner, file.path);
    const downloadFile: FileEntry = {
      ...file,
      ...info,
      name: info.name || file.name || file.path.split("/").filter(Boolean).pop() || file.path,
      path: file.path,
      type: "file",
    };
    await performDownload(
      downloadFile,
      `/v1/fs/shared-download?owner=${encodeURIComponent(owner)}&path=${encodeURIComponent(file.path)}`,
    );
  }, [performDownload]);

  React.useEffect(() => {
    localStorage.setItem("filemgr.rememberPasswordsOptIn", allowRememberPasswords ? "1" : "0");
  }, [allowRememberPasswords]);

  React.useEffect(() => {
    void purgeExpiredRememberedPasswords();
  }, []);

  const forgetRememberedForFile = React.useCallback(async (file: FileEntry) => {
    try {
      const encMeta = resolveEncryptionMetadata(file);
      const fileId = await buildRememberedFileId(file.path, encMeta);
      await clearRememberedPassword(fileId);
      toast.success(`Forgot remembered password for ${file.name}`);
    } catch {
      toast.error("Failed to forget remembered password for this file");
    }
  }, []);

  const clearAllRemembered = React.useCallback(async () => {
    try {
      const removed = await clearAllRememberedPasswords();
      toast.success(removed > 0 ? `Cleared ${removed} remembered password(s)` : "No remembered passwords to clear");
    } catch {
      toast.error("Failed to clear remembered passwords");
    }
  }, []);

  // ── Upload (button) — with presigned path for large files ──────

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const files = Array.from(e.target.files);

    let uploadPassword: string | null = null;
    if (encryptUploads) {
      const passwordResult = await requestPassword({
        title: "Set encryption password",
        description: "This password will be required to decrypt downloaded files.",
        confirm: true,
      });
      uploadPassword = passwordResult?.password ?? null;
      if (!uploadPassword) {
        e.target.value = "";
        return;
      }
    }

    for (const file of files) {
      const targetPath = currentPath.endsWith("/")
        ? currentPath + file.name
        : currentPath + "/" + file.name;
      const toastId = toast.loading(`Uploading ${file.name}...`);
      try {
        let uploadFileObj: File = file;
        let encMeta: EncryptionMetadata | null = null;
        if (encryptUploads && uploadPassword) {
          const encrypted = await encryptFileChunked(file, uploadPassword, {
            useWorker: true,
            onProgress: (p) => toast.loading(`Encrypting ${file.name}... ${p.percent}%`, { id: toastId }),
          });
          uploadFileObj = new File([encrypted.blob], file.name, { type: "application/octet-stream" });
          encMeta = encrypted.metadata;
        }

        if (uploadFileObj.size > PRESIGN_THRESHOLD) {
          const presign = await fsPresignUpload(targetPath, uploadFileObj.type || undefined);
          await fetch(presign.upload_url, {
            method: "PUT",
            headers: { "Content-Type": presign.content_type },
            body: uploadFileObj,
          });
          await completeUpload(
            presign.path,
            presign.key,
            presign.ticket_id,
            presign.content_type,
            encryptUploads ? { encrypted: true, encMeta } : undefined,
          );
        } else {
          await uploadFile(
            uploadFileObj,
            targetPath,
            encryptUploads ? { encrypted: true, encMeta } : undefined,
          );
        }
        toast.success(`Uploaded ${file.name}`, { id: toastId });
      } catch {
        toast.error(`Failed to upload ${file.name}`, { id: toastId });
      }
    }
    queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
    e.target.value = "";
  };

  // ── Upload ZIP ─────────────────────────────────────────────────

  const handleZipInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";
    const toastId = toast.loading(`Extracting ${file.name}...`);
    try {
      const result = await uploadZip(file, currentPath);
      toast.success(`Extracted ${result.count} file(s)`, { id: toastId });
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
    } catch {
      toast.error("Failed to upload ZIP", { id: toastId });
    }
  };

  const handleUploadComplete = () => {
    queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
  };

  // ── Move ──────────────────────────────────────────────────────

  const handleMoveOpen = (entry: FileEntry) => {
    setMoveTarget(entry);
    setMoveDialogOpen(true);
  };

  const handleBulkMoveOpen = () => {
    setMoveTarget(null); // null = bulk move
    setMoveDialogOpen(true);
  };

  const handleMove = async (targetFolder: string) => {
    setMoveLoading(true);
    try {
      if (moveTarget) {
        // Single file/folder move
        const dst = targetFolder.endsWith("/")
          ? targetFolder + moveTarget.name
          : targetFolder + "/" + moveTarget.name;
        await moveFile(moveTarget.path, dst);
        toast.success(`Moved "${moveTarget.name}"`);
      } else {
        // Bulk move
        const selected = displayItems.filter((f) => selectedKeys.has(f.path));
        for (const entry of selected) {
          const dst = targetFolder.endsWith("/")
            ? targetFolder + entry.name
            : targetFolder + "/" + entry.name;
          await moveFile(entry.path, dst);
        }
        toast.success(`Moved ${selectedKeys.size} item(s)`);
        setSelectedKeys(new Set());
      }
      queryClient.invalidateQueries({ queryKey: ["files"] });
      setMoveDialogOpen(false);
    } catch {
      toast.error("Failed to move");
    } finally {
      setMoveLoading(false);
    }
  };

  const usageSummary = usageSummaryQuery.data;
  const usageWarnings = [
    usageSummary ? { label: "Upload", percent: usageSummary.upload.percent_used } : null,
    usageSummary ? { label: "Download", percent: usageSummary.download.percent_used } : null,
    usageSummary ? { label: "Storage", percent: usageSummary.storage.percent_used } : null,
  ].filter((v): v is { label: string; percent: number } => !!v && warningLevel(v.percent) !== "none");
  const hasCriticalUsageWarning = usageWarnings.some((w) => warningLevel(w.percent) === "critical");

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-4">
      <PageHeader
        title="Files"
        description="Manage your files and folders"
      />
      <ImpersonationRouteIndicator area="files" />

      {usageWarnings.length > 0 && (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${hasCriticalUsageWarning ? "border-red-300 bg-red-50 text-red-800" : "border-amber-300 bg-amber-50 text-amber-800"}`}
          data-testid="usage-warning-banner"
        >
          <span className="font-medium">Usage warning:</span>{" "}
          {usageWarnings.map((w) => `${w.label} ${w.percent.toFixed(1)}%`).join(" · ")}
          <Link to="/billing?tab=usage" className="ml-2 underline">Review usage</Link>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="my-files">My Files</TabsTrigger>
          <TabsTrigger value="shared">Shared With Me</TabsTrigger>
        </TabsList>

        <TabsContent value="my-files" className="mt-4 space-y-4">
          {/* Breadcrumbs */}
          <nav className="flex items-center gap-1 text-sm overflow-x-auto">
            {pathSegments.map((seg, i) => (
              <React.Fragment key={seg.path}>
                {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />}
                <button
                  className="shrink-0 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                  onClick={() => handleBreadcrumb(seg.path)}
                >
                  {seg.label}
                </button>
              </React.Fragment>
            ))}
          </nav>

          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={searchMode === "name" ? "Search by name..." : "Search file contents..."}
                value={searchValue}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="pl-9"
              />
            </div>

            {/* Search mode toggle */}
            <button
              type="button"
              onClick={toggleSearchMode}
              className="rounded-full border px-3 py-1 text-xs font-medium transition-colors hover:bg-accent"
            >
              {searchMode === "name" ? "Name" : "Content"}
            </button>

            <label className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium">
              <input
                type="checkbox"
                checked={encryptUploads}
                onChange={(e) => setEncryptUploads(e.target.checked)}
              />
              <Lock className="h-3.5 w-3.5" />
              Encrypt uploads
            </label>

            <label className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium">
              <input
                type="checkbox"
                checked={allowRememberPasswords}
                onChange={(e) => setAllowRememberPasswords(e.target.checked)}
              />
              <ShieldCheck className="h-3.5 w-3.5" />
              Remember decrypt passwords on this device
            </label>
            <Button variant="ghost" size="sm" onClick={clearAllRemembered}>
              Clear remembered passwords
            </Button>

            <div className="rounded-md border px-3 py-1.5 text-xs" data-testid="files-usage-widget">
              {usageSummary ? (
                <div className="space-y-0.5">
                  <div>Storage: {formatBytesCompact(usageSummary.storage.used_bytes)} ({usageSummary.storage.percent_used.toFixed(1)}%)</div>
                  <div>Transfer: {formatBytesCompact(usageSummary.upload.used_bytes + usageSummary.download.used_bytes)}</div>
                  <Link to="/billing?tab=usage" className="text-primary underline">Usage &amp; Billing</Link>
                </div>
              ) : (
                <div className="text-muted-foreground">Loading usage…</div>
              )}
            </div>

            <div className="flex-1" />

            {/* Upload dropdown */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Upload className="h-4 w-4" />
                  <span className="hidden sm:inline ml-1">Upload</span>
                  <ChevronDown className="ml-1 h-3 w-3" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => fileInputRef.current?.click()}>
                  <Upload className="mr-2 h-4 w-4" /> Upload Files
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => zipInputRef.current?.click()}>
                  <Archive className="mr-2 h-4 w-4" /> Upload ZIP
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={handleFileInput}
            />
            <input
              ref={zipInputRef}
              type="file"
              accept=".zip,application/zip"
              className="hidden"
              onChange={handleZipInput}
            />

            <Button variant="outline" size="sm" onClick={() => setNewFolderOpen(true)}>
              <FolderPlus className="h-4 w-4" />
              <span className="hidden sm:inline ml-1">New Folder</span>
            </Button>
          </div>

          {/* Bulk actions toolbar */}
          <BulkActions
            selectedKeys={selectedKeys}
            items={displayItems}
            onClearSelection={() => setSelectedKeys(new Set())}
            onMoveSelected={handleBulkMoveOpen}
            onDeleted={() => {
              queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
            }}
          />

          {/* File table with drag-and-drop upload */}
          <UploadZone currentPath={currentPath} onUploadComplete={handleUploadComplete}>
            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : (
              <FileTable
                data={displayItems}
                sort={sort}
                onSort={setSort}
                selectedKeys={selectedKeys}
                onSelectionChange={setSelectedKeys}
                onNavigate={handleNavigate}
                onPreview={handlePreview}
                onDownload={handleDownload}
                onShare={(f) => setShareTarget(f)}
                onRename={(f) => { setRenameTarget(f); setRenameName(f.name); }}
                onMove={handleMoveOpen}
                onDelete={(f) => setDeleteTarget(f)}
                emptyState={
                  <EmptyState
                    icon={<FolderOpen className="h-6 w-6" />}
                    title={isSearching ? "No results" : "Empty folder"}
                    description={isSearching ? "Try a different search term" : "Upload files or create a folder to get started"}
                  />
                }
              />
            )}
          </UploadZone>
        </TabsContent>

        <TabsContent value="shared" className="mt-4">
          <SharedWithMe onPreviewShared={handlePreviewShared} onDownloadShared={handleSharedDownload} />
        </TabsContent>
      </Tabs>

      {/* New folder dialog */}
      <Dialog open={newFolderOpen} onOpenChange={setNewFolderOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Folder</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="folder-name">Folder name</Label>
            <Input
              id="folder-name"
              placeholder="Enter folder name"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newFolderName.trim()) createFolderMut.mutate(newFolderName.trim());
              }}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button
              onClick={() => createFolderMut.mutate(newFolderName.trim())}
              disabled={!newFolderName.trim() || createFolderMut.isPending}
            >
              {createFolderMut.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rename dialog */}
      <Dialog open={!!renameTarget} onOpenChange={(open) => { if (!open) setRenameTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="rename-input">New name</Label>
            <Input
              id="rename-input"
              value={renameName}
              onChange={(e) => setRenameName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && renameName.trim() && renameTarget) {
                  renameMut.mutate({ entry: renameTarget, newName: renameName.trim() });
                }
              }}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button
              onClick={() => renameTarget && renameMut.mutate({ entry: renameTarget, newName: renameName.trim() })}
              disabled={!renameName.trim() || renameMut.isPending}
            >
              {renameMut.isPending ? "Renaming..." : "Rename"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
        title={`Delete ${deleteTarget?.type === "folder" ? "folder" : "file"}?`}
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => deleteTarget && deleteMut.mutate(deleteTarget)}
        loading={deleteMut.isPending}
      />

      {/* Share dialog */}
      {shareTarget && (
        <ShareDialog
          open={!!shareTarget}
          onOpenChange={(open) => { if (!open) setShareTarget(null); }}
          filePath={shareTarget.path}
        />
      )}

      {/* Move dialog */}
      <MoveDialog
        open={moveDialogOpen}
        onOpenChange={setMoveDialogOpen}
        currentFolder={currentPath}
        onMove={handleMove}
        loading={moveLoading}
      />


      <Dialog open={passwordDialogOpen} onOpenChange={(open) => { if (!open) completePasswordDialog(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{passwordDialogTitle}</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            {passwordDialogDescription && <DialogDescription>{passwordDialogDescription}</DialogDescription>}
            <Label htmlFor="encryption-password">Password</Label>
            <Input
              id="encryption-password"
              type="password"
              value={passwordValue}
              onChange={(e) => setPasswordValue(e.target.value)}
              autoFocus
            />
            {requirePasswordConfirm && (
              <>
                <Label htmlFor="encryption-password-confirm">Confirm password</Label>
                <Input
                  id="encryption-password-confirm"
                  type="password"
                  value={passwordConfirmValue}
                  onChange={(e) => setPasswordConfirmValue(e.target.value)}
                />
              </>
            )}
            {requirePasswordConfirm && (() => {
              const policy = evaluateEncryptionPassword(passwordValue);
              return (
                <div className="rounded-md border p-2 text-xs">
                  <p className="mb-1 font-medium text-foreground">Password strength ({policy.score}/6)</p>
                  <ul className="space-y-1">
                    {policy.checks.map((check) => (
                      <li key={check.id} className={check.met ? "text-green-600" : "text-muted-foreground"}>
                        {check.met ? "✓" : "•"} {check.label}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })()}
            {allowRememberPasswordChoice && (
              <label className="flex items-center gap-2 pt-1 text-sm text-muted-foreground">
                <input
                  type="checkbox"
                  checked={rememberPasswordChoice}
                  onChange={(e) => setRememberPasswordChoice(e.target.checked)}
                />
                Remember this password in encrypted device storage
              </label>
            )}
            {allowRememberPasswordChoice && (
              <p className="text-xs text-muted-foreground">
                Optional and off by default. Stored only on this device in encrypted browser storage with a 90-day expiry.
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => completePasswordDialog(null)}>Cancel</Button>
            <Button
              onClick={() => completePasswordDialog({ password: passwordValue, remember: rememberPasswordChoice })}
              disabled={(() => {
                if (!passwordValue) return true;
                if (!requirePasswordConfirm) return false;
                const policy = evaluateEncryptionPassword(passwordValue);
                return passwordValue !== passwordConfirmValue || !policy.isStrong;
              })()}
            >
              Continue
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* File preview modal */}
      {previewContext && (
        <FilePreview
          file={previewContext.file}
          files={previewContext.files}
          onClose={() => setPreviewContext(null)}
          onNavigate={(f) => setPreviewContext((prev) => (prev ? { ...prev, file: f } : prev))}
          onDownload={(file) => {
            if (previewContext.source === "shared" && previewContext.sharedOwner) {
              void handleSharedPreviewDownload(previewContext.sharedOwner, file);
              return;
            }
            void handleDownload(file);
          }}
          onForgetRemembered={forgetRememberedForFile}
          previewSrcUrl={
            previewContext.source === "shared" && previewContext.sharedOwner
              ? sharedPreviewUrl(previewContext.sharedOwner, previewContext.file.path)
              : undefined
          }
        />
      )}
    </div>
  );
}
