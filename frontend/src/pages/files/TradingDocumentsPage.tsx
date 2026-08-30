// FE-170 (EPIC H) — Trading Documents area of the file manager.
// Lists statements / 1099s / trade confirmations (BE-171), grouped by type, and
// downloads each (BE-172) either via a presigned {download_url} (anchor navigate)
// or streamed bytes (fetch → blob → anchor — the FilesPage performDownload idiom).
// Share reuses the copy-link idiom. Everything DEGRADES-ON-404 to an honest
// "No trading documents yet" empty state — no crash.
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  FileText,
  FileCheck,
  FileSpreadsheet,
  Receipt,
  TrendingUp,
  Download,
  Share,
  ArrowLeft,
  Clock,
  Files as FilesIcon,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";

import {
  listTradingDocuments,
  getTradingDocumentDownloadUrl,
  tradingDocumentDownloadPath,
  type TradingDocument,
} from "@/api/endpoints/tradingDocuments";
import {
  groupDocuments,
  docTitle,
  docFilename,
  formatDocMeta,
  isDownloadable,
  TRADING_DOC_ICONS,
} from "@/lib/tradingDocuments";

// lucide component per icon KEY produced by the pure lib.
const ICON_BY_KEY: Record<string, typeof FileText> = {
  FileText,
  FileCheck,
  FileSpreadsheet,
  Receipt,
  TrendingUp,
};

/** Trigger a client-side file download from an in-memory blob (FilesPage idiom). */
function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Navigate the browser to a presigned URL to start a download. */
function navigateDownload(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  a.target = "_blank";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function handleDownload(doc: TradingDocument) {
  const filename = docFilename(doc);
  const toastId = toast.loading(`Preparing ${filename}...`);
  try {
    // Prefer an inline presigned URL, else resolve one from BE-172.
    let url = doc.download_url ?? null;
    if (!url) url = await getTradingDocumentDownloadUrl(doc.doc_id);

    if (url) {
      navigateDownload(url);
      toast.success(`Downloading ${filename}`, { id: toastId });
      return;
    }

    // No presigned URL → the endpoint streams bytes. Fetch → blob → anchor.
    const res = await fetch(tradingDocumentDownloadPath(doc.doc_id), { credentials: "include" });
    if (!res.ok) throw new Error(`download failed (${res.status})`);
    const blob = await res.blob();
    triggerDownload(blob, filename);
    toast.success(`Downloaded ${filename}`, { id: toastId });
  } catch {
    toast.error(`Could not download ${filename}`, { id: toastId });
  }
}

async function handleShare(doc: TradingDocument) {
  try {
    // Reuse the file-manager share idiom: resolve a shareable link and copy it.
    const url = doc.download_url ?? (await getTradingDocumentDownloadUrl(doc.doc_id));
    if (!url) {
      toast.error("No shareable link available for this document yet.");
      return;
    }
    const absolute = /^https?:\/\//.test(url) ? url : new URL(url, window.location.origin).href;
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(absolute);
      toast.success("Link copied to clipboard");
    } else {
      toast.success(absolute);
    }
  } catch {
    toast.error("Could not create a share link.");
  }
}

function DocRow({ doc }: { doc: TradingDocument }) {
  const iconKey = TRADING_DOC_ICONS[doc.type] ?? "FileText";
  const Icon = ICON_BY_KEY[iconKey] ?? FileText;
  const meta = formatDocMeta(doc);
  const generating = doc.status === "generating";
  const downloadable = isDownloadable(doc);

  return (
    <div
      className="flex items-center gap-3 rounded-md border px-3 py-2.5 hover:bg-accent/40 transition-colors"
      data-testid="trading-doc-row"
    >
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
        <Icon className="h-4.5 w-4.5" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate font-medium">{docTitle(doc)}</span>
          {generating && (
            <Badge variant="secondary" className="gap-1 text-[10px]">
              <Clock className="h-3 w-3" /> Generating
            </Badge>
          )}
        </div>
        {meta && <p className="truncate text-xs text-muted-foreground">{meta}</p>}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Button
          size="sm"
          variant="ghost"
          disabled={!downloadable}
          onClick={() => handleShare(doc)}
          title="Copy share link"
        >
          <Share className="h-4 w-4" />
          <span className="sr-only">Share</span>
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={!downloadable}
          onClick={() => handleDownload(doc)}
        >
          <Download className="mr-1.5 h-4 w-4" /> Download
        </Button>
      </div>
    </div>
  );
}

export default function TradingDocumentsPage() {
  const query = useQuery({
    queryKey: ["trading-documents"],
    queryFn: () => listTradingDocuments(),
    retry: false,
  });

  const groups = useMemo(
    () => groupDocuments(query.data?.documents ?? []),
    [query.data],
  );

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-4">
      <PageHeader
        title="Trading Documents"
        description="Statements, tax forms and trade confirmations"
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/files">
              <ArrowLeft className="mr-1.5 h-4 w-4" /> Back to Files
            </Link>
          </Button>
        }
      />

      {query.isLoading && (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-14 w-full rounded-md" />
          ))}
        </div>
      )}

      {!query.isLoading && groups.length === 0 && (
        <Card>
          <CardContent className="pt-6">
            <EmptyState
              icon={<FilesIcon className="h-8 w-8" />}
              title="No trading documents yet"
              description="Account statements, 1099s and trade confirmations will appear here once they are generated."
            />
          </CardContent>
        </Card>
      )}

      {!query.isLoading &&
        groups.map((group) => (
          <Card key={group.type}>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{group.label}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {group.documents.map((doc) => (
                <DocRow key={doc.doc_id} doc={doc} />
              ))}
            </CardContent>
          </Card>
        ))}
    </div>
  );
}
