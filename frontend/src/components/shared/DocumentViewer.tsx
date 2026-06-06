import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ZoomIn, ZoomOut, RotateCw, RotateCcw, Maximize } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/api/client";
import { cn } from "@/lib/utils";
import { VerificationStateBadge } from "./VerificationStateBadge";

/**
 * Shared identity-document viewer for KYC admin review (GAP-0246).
 *
 * Renders a tab bar (one tab per document type) with zoom / rotate / fullscreen
 * controls and a VerificationStateBadge overlay. Previously this logic lived
 * inline inside KycCaseDetailPage and could not be reused by other admin panels.
 *
 * Image source resolution:
 *  - When `document_id` is present we fetch a (presigned / mock) URL from the
 *    KYC document presign endpoint and cache it via React Query. The presigned
 *    URL is valid ~15 min on AWS, so we keep staleTime below that.
 *  - When `document_id` is absent (legacy file_ref records) we fall back to the
 *    generic file-manager download proxy keyed on `path`.
 */
export interface DocumentFile {
  type: string;
  /** Present on newer records; used to fetch a presigned URL. */
  document_id?: string | null;
  /** File-manager canonical path; proxy fallback when document_id is absent. */
  path?: string | null;
  verification_state: string;
  uploaded_at?: number;
}

const FILE_TYPE_LABELS: Record<string, string> = {
  selfie: "Selfie",
  id_front: "ID Front",
  id_back: "ID Back",
  proof_of_address: "Proof of Address",
};

function labelFor(type: string): string {
  return FILE_TYPE_LABELS[type] ?? type;
}

/** Fetch the presigned URL for a KYC document; cached + re-fetched before expiry. */
function usePresignedUrl(documentId: string) {
  return useQuery({
    queryKey: ["kyc-doc-url", documentId],
    queryFn: () =>
      api
        .get<{ url: string }>(`/ui/kyc/documents/${documentId}/presign`)
        .then((r) => r.url),
    enabled: !!documentId,
    staleTime: 10 * 60 * 1000, // 10 min — presigned URLs valid ~15 min
    gcTime: 12 * 60 * 1000,
  });
}

function PresignedImage({
  documentId,
  alt,
  style,
}: {
  documentId: string;
  alt: string;
  style: React.CSSProperties;
}) {
  const { data: url, isLoading, isError } = usePresignedUrl(documentId);
  if (isLoading) {
    return <p className="py-12 text-sm text-muted-foreground">Loading document…</p>;
  }
  if (isError || !url) {
    return <p className="py-12 text-sm text-destructive">Image unavailable.</p>;
  }
  return (
    <img
      src={url}
      alt={alt}
      className="max-w-full transition-transform"
      style={style}
      data-testid="doc-image"
    />
  );
}

function DocumentImage({
  file,
  style,
}: {
  file: DocumentFile;
  style: React.CSSProperties;
}) {
  const alt = labelFor(file.type);
  if (file.document_id) {
    return <PresignedImage documentId={file.document_id} alt={alt} style={style} />;
  }
  if (file.path) {
    return (
      <img
        src={`/ui/files/download?path=${encodeURIComponent(file.path)}`}
        alt={alt}
        className="max-w-full transition-transform"
        style={style}
        data-testid="doc-image"
      />
    );
  }
  return <p className="py-12 text-sm text-muted-foreground">No document source.</p>;
}

export function DocumentViewer({ files }: { files: DocumentFile[] }) {
  const [activeTab, setActiveTab] = useState(files[0]?.type ?? "");
  const [scale, setScale] = useState(1);
  const [rotation, setRotation] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);

  const zoomIn = useCallback(() => setScale((s) => Math.min(s + 0.25, 5)), []);
  const zoomOut = useCallback(() => setScale((s) => Math.max(s - 0.25, 0.25)), []);
  const rotateCw = useCallback(() => setRotation((r) => (r + 90) % 360), []);
  const rotateCcw = useCallback(() => setRotation((r) => (r - 90 + 360) % 360), []);

  const handleTabChange = useCallback((val: string) => {
    setActiveTab(val);
    setScale(1);
    setRotation(0);
  }, []);

  const handleWheel = useCallback(
    (e: React.WheelEvent) => {
      e.preventDefault();
      if (e.deltaY < 0) {
        zoomIn();
      } else {
        zoomOut();
      }
    },
    [zoomIn, zoomOut],
  );

  if (files.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          No documents attached to this case.
        </CardContent>
      </Card>
    );
  }

  const imageStyle: React.CSSProperties = {
    transform: `scale(${scale}) rotate(${rotation}deg)`,
  };

  const viewer = (
    <div
      className={cn(fullscreen && "fixed inset-0 z-50 flex flex-col bg-background")}
      role={fullscreen ? "dialog" : undefined}
      aria-modal={fullscreen ? true : undefined}
      aria-label={fullscreen ? "Document viewer fullscreen" : undefined}
    >
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <div className="flex items-center justify-between border-b px-4 py-2">
          <TabsList>
            {files.map((file) => (
              <TabsTrigger
                key={file.type}
                value={file.type}
                data-testid={`doc-tab-${file.type}`}
              >
                {labelFor(file.type)}
              </TabsTrigger>
            ))}
          </TabsList>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="icon" onClick={zoomIn} aria-label="Zoom In">
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={zoomOut} aria-label="Zoom Out">
              <ZoomOut className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={rotateCw} aria-label="Rotate CW">
              <RotateCw className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={rotateCcw} aria-label="Rotate CCW">
              <RotateCcw className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setFullscreen((f) => !f)}
              aria-label="Fullscreen"
              aria-pressed={fullscreen}
            >
              <Maximize className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {files.map((file) => (
          <TabsContent key={file.type} value={file.type} className="mt-0">
            <div
              className="relative flex items-center justify-center overflow-auto bg-muted/30"
              style={{ minHeight: fullscreen ? "calc(100vh - 60px)" : "400px" }}
              onWheel={handleWheel}
            >
              {file.type === activeTab && (
                <DocumentImage file={file} style={imageStyle} />
              )}
              <div className="absolute bottom-3 right-3">
                <VerificationStateBadge state={file.verification_state} />
              </div>
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );

  return <Card className="overflow-hidden">{viewer}</Card>;
}
