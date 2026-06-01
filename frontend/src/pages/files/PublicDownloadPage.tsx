import React from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Download, FileText, Lock, Loader2, AlertCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  getShareLinkInfo,
  downloadShareLink,
} from "@/api/endpoints/fileShareLinks";

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function unavailableMessage(info: {
  is_revoked: boolean;
  is_expired: boolean;
  is_used: boolean;
}): string | null {
  if (info.is_revoked) return "This link has been revoked by the owner.";
  if (info.is_expired) return "This link has expired.";
  if (info.is_used) return "This link has already been used.";
  return null;
}

export default function PublicDownloadPage() {
  const { linkId = "" } = useParams<{ linkId: string }>();
  const [password, setPassword] = React.useState("");
  const [downloading, setDownloading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["public-share-info", linkId],
    queryFn: () => getShareLinkInfo(linkId),
    retry: false,
    enabled: !!linkId,
  });

  const handleDownload = async () => {
    setError(null);
    setDownloading(true);
    try {
      const { blob, fileName } = await downloadShareLink(
        linkId,
        password || undefined,
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = data?.file_name || fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      const err = e as { status?: number; detail?: string };
      if (err.status === 403) setError("Invalid password.");
      else if (err.status === 410) setError("This link is no longer available.");
      else setError("Download failed. Please try again.");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div
      className="flex min-h-screen items-center justify-center bg-muted/30 p-4"
      data-testid="public-download-page"
    >
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" /> Secure file download
          </CardTitle>
          <CardDescription>
            Someone shared an encrypted file with you.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading…
            </div>
          ) : isError || !data ? (
            <div
              className="flex items-center gap-2 text-destructive"
              data-testid="share-link-error"
            >
              <AlertCircle className="h-4 w-4" /> Share link not found.
            </div>
          ) : unavailableMessage(data) ? (
            <div
              className="flex items-center gap-2 text-destructive"
              data-testid="share-link-error"
            >
              <AlertCircle className="h-4 w-4" /> {unavailableMessage(data)}
            </div>
          ) : (
            <>
              <div className="rounded-md border p-3">
                <p className="font-medium" data-testid="share-link-filename">
                  {data.file_name}
                </p>
                <p className="text-sm text-muted-foreground">
                  {formatBytes(data.file_size_bytes)} · {data.content_type}
                </p>
              </div>

              {data.requires_password && (
                <div className="space-y-2">
                  <Label htmlFor="dl-pass" className="flex items-center gap-1">
                    <Lock className="h-3 w-3" /> Password
                  </Label>
                  <Input
                    id="dl-pass"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    data-testid="public-download-password"
                  />
                </div>
              )}

              {error && (
                <p className="text-sm text-destructive" data-testid="share-link-error">
                  {error}
                </p>
              )}

              <Button
                className="w-full"
                onClick={handleDownload}
                disabled={downloading || (data.requires_password && !password)}
                data-testid="public-download-button"
              >
                {downloading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Download className="h-4 w-4" />
                )}
                Download
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
