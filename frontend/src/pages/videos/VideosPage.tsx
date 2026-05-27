import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Video,
  Upload,
  MoreVertical,
  Pencil,
  Trash2,
  Copy,
  X,
  Film,
  CloudUpload,
  Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import CombineVideosDialog from "@/components/shared/CombineVideosDialog";
import {
  presignVideoUpload,
  completeVideoUpload,
  listMyVideos,
  updateVideo,
  deleteVideo,
  type VideoListItem,
  type VideoUpdateRequest,
} from "@/api/endpoints/videos";

// ─── Upload State Machine ────────────────────────────────────────────────────

type UploadStatus =
  | "idle"
  | "presigning"
  | "uploading"
  | "confirming"
  | "processing"
  | "ready"
  | "cancelled"
  | "error";

interface UploadItem {
  id: string;
  file: File;
  title: string;
  description: string;
  visibility: "private" | "public" | "unlisted";
  status: UploadStatus;
  progress: number;
  videoId: string | null;
  error: string | null;
  xhr: XMLHttpRequest | null;
}

type UploadAction =
  | { type: "ADD_FILES"; files: File[] }
  | { type: "SET_STATUS"; id: string; status: UploadStatus; error?: string }
  | { type: "SET_PROGRESS"; id: string; progress: number }
  | { type: "SET_VIDEO_ID"; id: string; videoId: string }
  | { type: "SET_XHR"; id: string; xhr: XMLHttpRequest }
  | { type: "UPDATE_META"; id: string; title?: string; description?: string; visibility?: "private" | "public" | "unlisted" }
  | { type: "REMOVE"; id: string }
  | { type: "CANCEL"; id: string }
  | { type: "CLEAR_COMPLETED" };

function uploadReducer(state: UploadItem[], action: UploadAction): UploadItem[] {
  switch (action.type) {
    case "ADD_FILES":
      return [
        ...state,
        ...action.files.map((file) => ({
          id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          file,
          title: file.name.replace(/\.[^.]+$/, ""),
          description: "",
          visibility: "private" as const,
          status: "idle" as UploadStatus,
          progress: 0,
          videoId: null,
          error: null,
          xhr: null,
        })),
      ];
    case "SET_STATUS":
      return state.map((item) =>
        item.id === action.id
          ? { ...item, status: action.status, error: action.error ?? item.error }
          : item,
      );
    case "SET_PROGRESS":
      return state.map((item) =>
        item.id === action.id ? { ...item, progress: action.progress } : item,
      );
    case "SET_VIDEO_ID":
      return state.map((item) =>
        item.id === action.id ? { ...item, videoId: action.videoId } : item,
      );
    case "SET_XHR":
      return state.map((item) =>
        item.id === action.id ? { ...item, xhr: action.xhr } : item,
      );
    case "UPDATE_META":
      return state.map((item) =>
        item.id === action.id
          ? {
              ...item,
              title: action.title ?? item.title,
              description: action.description ?? item.description,
              visibility: action.visibility ?? item.visibility,
            }
          : item,
      );
    case "REMOVE":
      return state.filter((item) => item.id !== action.id);
    case "CANCEL": {
      const target = state.find((i) => i.id === action.id);
      if (target?.xhr) {
        target.xhr.abort();
      }
      return state.map((item) =>
        item.id === action.id ? { ...item, status: "cancelled", xhr: null } : item,
      );
    }
    case "CLEAR_COMPLETED":
      return state.filter(
        (item) => !["ready", "cancelled", "error"].includes(item.status),
      );
    default:
      return state;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || seconds <= 0) return "--:--";
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}:${secs.toString().padStart(2, "0")}`;
}

function formatFileSize(bytes: number | null | undefined): string {
  if (bytes == null || bytes <= 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function getStatusBadge(status: string) {
  switch (status) {
    case "created":
    case "probing":
    case "encoding":
      return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">Processing</Badge>;
    case "approved":
    case "published":
    case "ready":
      return <Badge variant="secondary" className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Ready</Badge>;
    case "failed":
    case "rejected":
      return <Badge variant="destructive">Failed</Badge>;
    case "deleted":
      return <Badge variant="secondary" className="bg-red-100 text-red-800">Deleted</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

// ─── ALLOWED TYPES ──────────────────────────────────────────────────────────

const ALLOWED_TYPES = [
  "video/mp4",
  "video/webm",
  "video/quicktime",
  "video/x-msvideo",
  "video/x-matroska",
];

const ACCEPT_STRING = ALLOWED_TYPES.join(",");

// ─── Main Component ─────────────────────────────────────────────────────────

export default function VideosPage() {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploads, dispatch] = useReducer(uploadReducer, []);
  const [isDragOver, setIsDragOver] = useState(false);
  const [editVideo, setEditVideo] = useState<VideoListItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<VideoListItem | null>(null);
  const [combineOpen, setCombineOpen] = useState(false);

  // ─── Video List Query ────────────────────────────────────────────────────
  const {
    data: videoList,
    isLoading,
  } = useQuery({
    queryKey: ["vod", "videos"],
    queryFn: () => listMyVideos({ limit: 50 }),
    refetchInterval: uploads.some((u) => u.status === "processing") ? 5000 : false,
  });

  // ─── Mutations ────────────────────────────────────────────────────────────
  const deleteMutation = useMutation({
    mutationFn: (videoId: string) => deleteVideo(videoId),
    onSuccess: () => {
      toast.success("Video deleted");
      queryClient.invalidateQueries({ queryKey: ["vod", "videos"] });
      setDeleteTarget(null);
    },
    onError: () => {
      toast.error("Failed to delete video");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ videoId, body }: { videoId: string; body: VideoUpdateRequest }) =>
      updateVideo(videoId, body),
    onSuccess: () => {
      toast.success("Video updated");
      queryClient.invalidateQueries({ queryKey: ["vod", "videos"] });
      setEditVideo(null);
    },
    onError: () => {
      toast.error("Failed to update video");
    },
  });

  // ─── Upload Logic ─────────────────────────────────────────────────────────

  const startUpload = useCallback(
    async (item: UploadItem) => {
      const { id, file } = item;

      try {
        // 1. Presign
        dispatch({ type: "SET_STATUS", id, status: "presigning" });
        const presign = await presignVideoUpload({
          filename: file.name,
          content_type: file.type || "video/mp4",
          size_bytes: file.size,
        });
        dispatch({ type: "SET_VIDEO_ID", id, videoId: presign.video_id });

        // 2. XHR Upload with progress
        dispatch({ type: "SET_STATUS", id, status: "uploading" });

        await new Promise<void>((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          dispatch({ type: "SET_XHR", id, xhr });

          xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
              dispatch({
                type: "SET_PROGRESS",
                id,
                progress: Math.round((e.loaded / e.total) * 100),
              });
            }
          };

          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
              resolve();
            } else {
              reject(new Error(`Upload failed with status ${xhr.status}`));
            }
          };

          xhr.onerror = () => reject(new Error("Network error during upload"));
          xhr.onabort = () => reject(new Error("Upload cancelled"));

          xhr.open("PUT", presign.presigned_url);
          xhr.setRequestHeader("Content-Type", file.type || "video/mp4");
          xhr.send(file);
        });

        // 3. Complete upload
        dispatch({ type: "SET_STATUS", id, status: "confirming" });
        await completeVideoUpload(presign.video_id);

        // 4. Processing state (backend handles transcoding)
        dispatch({ type: "SET_STATUS", id, status: "processing" });
        dispatch({ type: "SET_PROGRESS", id, progress: 100 });

        toast.success(`Upload complete: ${item.title}`);
        queryClient.invalidateQueries({ queryKey: ["vod", "videos"] });

        // Mark as ready after a short delay (the backend may still be processing)
        setTimeout(() => {
          dispatch({ type: "SET_STATUS", id, status: "ready" });
        }, 2000);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Upload failed";
        if (message === "Upload cancelled") {
          dispatch({ type: "SET_STATUS", id, status: "cancelled" });
        } else {
          dispatch({ type: "SET_STATUS", id, status: "error", error: message });
          toast.error(`Upload failed: ${message}`);
        }
      }
    },
    [queryClient],
  );

  // Auto-start uploads when new files are added
  useEffect(() => {
    const idle = uploads.filter((u) => u.status === "idle");
    for (const item of idle) {
      startUpload(item);
    }
  }, [uploads, startUpload]);

  // ─── File handling ────────────────────────────────────────────────────────

  const handleFiles = useCallback((files: FileList | File[]) => {
    const validFiles = Array.from(files).filter((f) => {
      if (!ALLOWED_TYPES.includes(f.type)) {
        toast.error(`Unsupported format: ${f.name}`);
        return false;
      }
      if (f.size > 10 * 1024 * 1024 * 1024) {
        toast.error(`File too large (max 10 GB): ${f.name}`);
        return false;
      }
      return true;
    });
    if (validFiles.length > 0) {
      dispatch({ type: "ADD_FILES", files: validFiles });
    }
  }, []);

  // ─── Drag & Drop ─────────────────────────────────────────────────────────

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);
      if (e.dataTransfer.files.length > 0) {
        handleFiles(e.dataTransfer.files);
      }
    },
    [handleFiles],
  );

  // ─── Render ───────────────────────────────────────────────────────────────

  const activeUploads = uploads.filter(
    (u) => !["ready", "cancelled", "error"].includes(u.status),
  );
  const hasUploads = uploads.length > 0;
  const videos = videoList?.items ?? [];

  return (
    <div
      className="relative flex flex-col gap-6 p-4 md:p-6"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {isDragOver && (
        <div className="absolute inset-0 z-50 flex items-center justify-center rounded-lg border-2 border-dashed border-primary bg-primary/5 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-2 text-primary">
            <CloudUpload className="h-12 w-12" />
            <p className="text-lg font-semibold">Drop videos here to upload</p>
            <p className="text-sm text-muted-foreground">
              MP4, WebM, MOV, AVI, MKV up to 10 GB
            </p>
          </div>
        </div>
      )}

      {/* Page Header */}
      <PageHeader
        title="Videos"
        description="Upload, manage, and publish your video content"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setCombineOpen(true)}>
              <Layers className="mr-2 h-4 w-4" />
              Combine Videos
            </Button>
            <Button onClick={() => fileInputRef.current?.click()}>
              <Upload className="mr-2 h-4 w-4" />
              Upload Video
            </Button>
          </div>
        }
      />

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept={ACCEPT_STRING}
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files && e.target.files.length > 0) {
            handleFiles(e.target.files);
            e.target.value = "";
          }
        }}
      />

      {/* Upload Panel */}
      {hasUploads && (
        <Card>
          <CardContent className="p-4">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold">
                Uploads ({activeUploads.length} active)
              </h3>
              {uploads.some((u) =>
                ["ready", "cancelled", "error"].includes(u.status),
              ) && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => dispatch({ type: "CLEAR_COMPLETED" })}
                >
                  Clear completed
                </Button>
              )}
            </div>
            <div className="space-y-3">
              {uploads.map((item) => (
                <UploadItemRow
                  key={item.id}
                  item={item}
                  onCancel={() => dispatch({ type: "CANCEL", id: item.id })}
                  onRemove={() => dispatch({ type: "REMOVE", id: item.id })}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Video Library Grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-0">
                <Skeleton className="aspect-video w-full rounded-t-lg" />
                <div className="space-y-2 p-3">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : videos.length === 0 ? (
        <EmptyState
          icon={<Film className="h-8 w-8" />}
          title="No videos yet"
          description="Upload your first video to get started. Drag and drop files here or click the Upload button."
          action={{
            label: "Upload Video",
            onClick: () => fileInputRef.current?.click(),
          }}
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {videos.map((video) => (
            <VideoCard
              key={video.video_id}
              video={video}
              onEdit={() => setEditVideo(video)}
              onDelete={() => setDeleteTarget(video)}
            />
          ))}
        </div>
      )}

      {/* Edit Video Dialog */}
      {editVideo && (
        <EditVideoDialog
          video={editVideo}
          open={!!editVideo}
          onOpenChange={(open) => {
            if (!open) setEditVideo(null);
          }}
          onSave={(body) =>
            updateMutation.mutate({ videoId: editVideo.video_id, body })
          }
          loading={updateMutation.isPending}
        />
      )}

      {/* Delete Confirm Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
        title="Delete Video"
        description={`Are you sure you want to delete "${deleteTarget?.title}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => {
          if (deleteTarget) {
            deleteMutation.mutate(deleteTarget.video_id);
          }
        }}
        loading={deleteMutation.isPending}
      />

      {/* Combine Videos Dialog (VOD-016) */}
      <CombineVideosDialog open={combineOpen} onOpenChange={setCombineOpen} />
    </div>
  );
}

// ─── Upload Item Row ────────────────────────────────────────────────────────

function UploadItemRow({
  item,
  onCancel,
  onRemove,
}: {
  item: UploadItem;
  onCancel: () => void;
  onRemove: () => void;
}) {
  const isActive = ["presigning", "uploading", "confirming", "processing"].includes(
    item.status,
  );
  const isDone = ["ready", "cancelled", "error"].includes(item.status);

  return (
    <div className="flex items-center gap-3 rounded-md border p-3">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded bg-muted">
        <Video className="h-5 w-5 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="truncate text-sm font-medium">{item.title}</p>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {formatFileSize(item.file.size)}
          </span>
          {item.status === "uploading" && (
            <span className="text-xs text-muted-foreground">
              {item.progress}%
            </span>
          )}
          {item.status === "error" && (
            <span className="text-xs text-destructive">{item.error}</span>
          )}
          {item.status === "cancelled" && (
            <span className="text-xs text-muted-foreground">Cancelled</span>
          )}
          {item.status === "presigning" && (
            <span className="text-xs text-muted-foreground">Preparing...</span>
          )}
          {item.status === "confirming" && (
            <span className="text-xs text-muted-foreground">Confirming...</span>
          )}
          {item.status === "processing" && (
            <span className="text-xs text-muted-foreground">Processing...</span>
          )}
          {item.status === "ready" && (
            <span className="text-xs text-green-600">Complete</span>
          )}
        </div>
        {item.status === "uploading" && (
          <Progress value={item.progress} className="mt-1 h-1.5" />
        )}
      </div>
      <div className="shrink-0">
        {isActive && (
          <Button variant="ghost" size="icon" onClick={onCancel} title="Cancel upload">
            <X className="h-4 w-4" />
          </Button>
        )}
        {isDone && (
          <Button variant="ghost" size="icon" onClick={onRemove} title="Remove">
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}

// ─── Video Card ─────────────────────────────────────────────────────────────

function VideoCard({
  video,
  onEdit,
  onDelete,
}: {
  video: VideoListItem;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const navigate = useNavigate();
  const handleCopyId = () => {
    navigator.clipboard.writeText(video.video_id);
    toast.success("Video ID copied to clipboard");
  };

  return (
    <Card className="group overflow-hidden transition-shadow hover:shadow-md">
      <CardContent className="p-0">
        {/* Thumbnail */}
        <div
          className="relative aspect-video w-full bg-muted cursor-pointer"
          onClick={() => navigate(`/videos/${video.video_id}`)}
          data-testid={`video-card-${video.video_id}`}
        >
          {video.thumbnail_url ? (
            <img
              src={video.thumbnail_url}
              alt={video.title}
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center">
              <Film className="h-10 w-10 text-muted-foreground/40" />
            </div>
          )}
          {/* Duration badge */}
          {video.duration_seconds != null && video.duration_seconds > 0 && (
            <div className="absolute bottom-2 right-2 rounded bg-black/70 px-1.5 py-0.5 text-xs font-medium text-white">
              {formatDuration(video.duration_seconds)}
            </div>
          )}
          {/* Status badge */}
          <div className="absolute left-2 top-2">
            {getStatusBadge(video.status)}
          </div>
        </div>

        {/* Info */}
        <div className="p-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0 flex-1">
              <h4 className="truncate text-sm font-medium" title={video.title}>
                {video.title}
              </h4>
              <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                {video.file_size_bytes && (
                  <span>{formatFileSize(video.file_size_bytes)}</span>
                )}
                <span>{video.visibility}</span>
              </div>
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <MoreVertical className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={onEdit}>
                  <Pencil className="mr-2 h-4 w-4" />
                  Edit
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleCopyId}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy ID
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={onDelete}
                  className="text-destructive focus:text-destructive"
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Edit Video Dialog ──────────────────────────────────────────────────────

function EditVideoDialog({
  video,
  open,
  onOpenChange,
  onSave,
  loading,
}: {
  video: VideoListItem;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSave: (body: VideoUpdateRequest) => void;
  loading: boolean;
}) {
  const [title, setTitle] = useState(video.title);
  const [description, setDescription] = useState("");
  const [visibility, setVisibility] = useState(video.visibility);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Video</DialogTitle>
          <DialogDescription>
            Update video metadata and visibility settings.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="edit-title">Title</Label>
            <Input
              id="edit-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Video title"
              maxLength={256}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-description">Description</Label>
            <Textarea
              id="edit-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              maxLength={2000}
              rows={3}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-visibility">Visibility</Label>
            <Select value={visibility} onValueChange={setVisibility}>
              <SelectTrigger id="edit-visibility">
                <SelectValue placeholder="Select visibility" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="private">Private</SelectItem>
                <SelectItem value="public">Public</SelectItem>
                <SelectItem value="unlisted">Unlisted</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={loading}
          >
            Cancel
          </Button>
          <Button
            onClick={() => {
              const body: VideoUpdateRequest = {};
              if (title !== video.title) body.title = title;
              if (description) body.description = description;
              if (visibility !== video.visibility) body.visibility = visibility;
              onSave(body);
            }}
            disabled={loading || !title.trim()}
          >
            {loading ? "Saving..." : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
