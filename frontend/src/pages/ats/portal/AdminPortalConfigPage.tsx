/**
 * Admin career portal config page (PRT-001).
 * Route: /ats/applications  (admin-facing, session auth required)
 *
 * Allows ADMIN/ROOT users to configure:
 *   - Portal name
 *   - Introduction / hero copy
 *   - Logo (via file-manager path)
 *   - Primary color
 *   - Support email
 *
 * Uses GET/PUT /ui/admin/career-portal/config.
 * Shows a friendly "not enabled" state when CAREER_PORTAL_ENABLED=0.
 *
 * Also serves as the applications review entry-point, linking out to the
 * public job board and displaying portal health info.
 */

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Settings, Loader2, AlertCircle, ExternalLink } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

import {
  getAdminPortalConfig,
  updateAdminPortalConfig,
  isCareerPortalNotEnabled,
  type CareerPortalConfigIn,
} from "@/api/endpoints/careerPortal";

// ─── Helpers ─────────────────────────────────────────────────────

function fmt(ts: number | null | undefined): string {
  if (!ts) return "Never";
  return new Date(ts * 1000).toLocaleString();
}

// ─── Page ─────────────────────────────────────────────────────────

export default function AdminPortalConfigPage() {
  const qc = useQueryClient();

  const configQuery = useQuery({
    queryKey: ["career-portal", "admin-config"],
    queryFn: getAdminPortalConfig,
    retry: (count, err) => !isCareerPortalNotEnabled(err) && count < 2,
    staleTime: 30_000,
  });

  // Form fields (initialised from query data)
  const [portalName, setPortalName] = useState("");
  const [introCopy, setIntroCopy] = useState("");
  const [logoFilePath, setLogoFilePath] = useState("");
  const [primaryColor, setPrimaryColor] = useState("");
  const [supportEmail, setSupportEmail] = useState("");

  const isDisabled = isCareerPortalNotEnabled(configQuery.error);

  // Sync form state from server config once loaded
  useEffect(() => {
    const d = configQuery.data;
    if (!d) return;
    setPortalName(d.portal_name ?? "");
    setIntroCopy(d.intro_copy ?? "");
    setLogoFilePath(d.logo_file_path ?? "");
    setPrimaryColor(d.primary_color ?? "");
    setSupportEmail(d.support_email ?? "");
  }, [configQuery.data]);

  const saveMut = useMutation({
    mutationFn: () => {
      const body: CareerPortalConfigIn = {
        portal_name: portalName.trim(),
        intro_copy: introCopy,
        logo_file_path: logoFilePath.trim() || null,
        primary_color: primaryColor.trim() || null,
        support_email: supportEmail.trim() || null,
      };
      return updateAdminPortalConfig(body);
    },
    onSuccess: (data) => {
      toast.success("Career portal config saved.");
      qc.setQueryData(["career-portal", "admin-config"], data);
      // Invalidate public config cache too
      void qc.invalidateQueries({ queryKey: ["career-portal", "config"] });
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Failed to save config.");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!portalName.trim()) {
      toast.error("Portal name is required.");
      return;
    }
    if (primaryColor && !/^#[0-9a-fA-F]{6}$/.test(primaryColor)) {
      toast.error("Primary color must be a 6-digit hex code (e.g. #3b82f6).");
      return;
    }
    saveMut.mutate();
  };

  // ── Not enabled ───────────────────────────────────────────────

  if (isDisabled) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Career Portal"
          description="Public job board & application settings"
        />
        <Card>
          <CardContent className="py-12 flex flex-col items-center gap-3 text-center">
            <AlertCircle className="h-10 w-10 text-muted-foreground/40" />
            <div>
              <p className="font-medium">Career portal is not enabled</p>
              <p className="text-sm text-muted-foreground mt-1">
                Set <code className="text-xs bg-muted px-1 py-0.5 rounded">CAREER_PORTAL_ENABLED=1</code>{" "}
                in your environment and restart the backend to activate the public job board.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── Loading ───────────────────────────────────────────────────

  if (configQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // ── Error ─────────────────────────────────────────────────────

  if (configQuery.isError && !isDisabled) {
    return (
      <div className="space-y-6">
        <PageHeader title="Career Portal" />
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
          <AlertCircle className="h-8 w-8 text-destructive" />
          <p className="text-sm text-muted-foreground">
            {(configQuery.error as Error)?.message ?? "Failed to load portal config."}
          </p>
          <Button variant="outline" onClick={() => void configQuery.refetch()}>
            Retry
          </Button>
        </div>
      </div>
    );
  }

  const config = configQuery.data;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Career Portal"
        description="Configure the public-facing job board branding and settings."
        actions={
          <Button asChild variant="outline" size="sm">
            <a href="/ats/portal/jobs" target="_blank" rel="noopener noreferrer">
              <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
              Preview job board
            </a>
          </Button>
        }
      />

      {/* Status card */}
      {config && (
        <Card className="bg-muted/40">
          <CardContent className="py-3 px-4 flex flex-wrap gap-4 text-xs text-muted-foreground">
            <span>
              Last updated:{" "}
              <span className="text-foreground">{fmt(config.updated_at)}</span>
            </span>
            {config.updated_by && (
              <span>
                By: <span className="text-foreground font-mono">{config.updated_by}</span>
              </span>
            )}
          </CardContent>
        </Card>
      )}

      {/* Config form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Settings className="h-4 w-4" /> Branding &amp; Settings
          </CardTitle>
          <CardDescription>
            Changes are reflected immediately on the public job board.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-1.5">
              <Label htmlFor="portalName">
                Portal name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="portalName"
                value={portalName}
                onChange={(e) => setPortalName(e.target.value)}
                placeholder="Acme Careers"
                maxLength={120}
                required
                disabled={saveMut.isPending}
              />
              <p className="text-xs text-muted-foreground">
                Displayed as the job board heading and in the RSS feed title.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="introCopy">Introduction text</Label>
              <Textarea
                id="introCopy"
                value={introCopy}
                onChange={(e) => setIntroCopy(e.target.value)}
                placeholder="Join our team and help us build something great…"
                rows={4}
                maxLength={4000}
                disabled={saveMut.isPending}
              />
              <p className="text-xs text-muted-foreground">
                Shown below the portal heading. {introCopy.length}/4000 characters.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="primaryColor">Primary color</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="primaryColor"
                    value={primaryColor}
                    onChange={(e) => setPrimaryColor(e.target.value)}
                    placeholder="#3b82f6"
                    maxLength={7}
                    disabled={saveMut.isPending}
                    className="font-mono"
                  />
                  {primaryColor && /^#[0-9a-fA-F]{6}$/.test(primaryColor) && (
                    <span
                      className="h-8 w-8 rounded border shrink-0"
                      style={{ backgroundColor: primaryColor }}
                    />
                  )}
                </div>
                <p className="text-xs text-muted-foreground">6-digit hex, e.g. #3b82f6</p>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="supportEmail">Support email</Label>
                <Input
                  id="supportEmail"
                  type="email"
                  value={supportEmail}
                  onChange={(e) => setSupportEmail(e.target.value)}
                  placeholder="careers@example.com"
                  maxLength={254}
                  disabled={saveMut.isPending}
                />
                <p className="text-xs text-muted-foreground">
                  Shown on the job board when no openings are available.
                </p>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="logoFilePath">Logo file path</Label>
              <Input
                id="logoFilePath"
                value={logoFilePath}
                onChange={(e) => setLogoFilePath(e.target.value)}
                placeholder="/career-portal/logo.png"
                disabled={saveMut.isPending}
              />
              <p className="text-xs text-muted-foreground">
                Path to a file in the file manager (e.g.{" "}
                <code className="text-xs">/career-portal/logo.png</code>). Upload
                via Files first, then paste the path here.
              </p>
              {config?.logo_url && (
                <div className="mt-2">
                  <img
                    src={config.logo_url}
                    alt="Current logo"
                    className="h-10 w-auto rounded border"
                  />
                  <p className="text-xs text-muted-foreground mt-1">Current logo</p>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <Button
                type="submit"
                disabled={saveMut.isPending || !portalName.trim()}
              >
                {saveMut.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Saving…
                  </>
                ) : (
                  "Save Configuration"
                )}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Quick links */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Quick links</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Button asChild variant="outline" size="sm">
            <a
              href="/public/careers/jobs"
              target="_blank"
              rel="noopener noreferrer"
            >
              <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
              Public jobs API
            </a>
          </Button>
          <Button asChild variant="outline" size="sm">
            <a
              href="/public/careers/jobs.rss"
              target="_blank"
              rel="noopener noreferrer"
            >
              <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
              RSS feed
            </a>
          </Button>
          <Button asChild variant="outline" size="sm">
            <a href="/ats/portal/jobs" target="_blank" rel="noopener noreferrer">
              <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
              Job board UI
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
