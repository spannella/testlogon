import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  activateKycTemplateVersion,
  archiveKycTemplate,
  createKycTemplate,
  deactivateKycTemplateVersion,
  listKycTemplates,
  previewKycTemplateUrl,
  uploadKycTemplateVersion,
} from "@/api/endpoints/kycDocumentTemplates";
import type {
  KycDocumentTemplate,
  KycTemplateTier,
} from "@/api/types";

const TIERS: KycTemplateTier[] = ["none", "tier_1", "tier_2", "tier_3"];

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "active") return "default";
  if (status === "archived") return "destructive";
  return "secondary";
}

// Tiny valid base64-encoded PDF used as a stand-in when no file is selected.
const SAMPLE_PDF_BASE64 =
  "JVBERi0xLjQKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+PgplbmRvYmoK" +
  "MiAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PgplbmRvYmoKMyAw" +
  "IG9iago8PC9UeXBlL1BhZ2UvUGFyZW50IDIgMCBSL01lZGlhQm94WzAgMCA2MTIgNzkyXT4+" +
  "CmVuZG9iagp4cmVmCjAgNAowMDAwMDAwMDAwIDY1NTM1IGYgCnRyYWlsZXIKPDwvU2l6ZSA0" +
  "L1Jvb3QgMSAwIFI+PgpzdGFydHhyZWYKMAolJUVPRg==";

async function fileToBase64(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i] ?? 0);
  return btoa(binary);
}

export default function KycDocumentTemplatesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<KycDocumentTemplate | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [tier, setTier] = useState<KycTemplateTier>("tier_1");
  const [placeholders, setPlaceholders] = useState("full_name, address_line_1, city, date_of_birth, current_date");

  const templatesQuery = useQuery({
    queryKey: ["kyc", "document-templates"],
    queryFn: async () => (await listKycTemplates()).items,
    staleTime: 30_000,
  });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["kyc", "document-templates"] });

  const createMut = useMutation({
    mutationFn: async () => {
      const tpl = await createKycTemplate({
        slug: slug.trim(),
        display_name: displayName.trim(),
        description: description.trim() || null,
        required_tier: tier,
        placeholder_fields: placeholders
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
      });
      // Auto-attach a placeholder PDF version so the template is renderable.
      await uploadKycTemplateVersion(tpl.template_id, SAMPLE_PDF_BASE64);
      return tpl;
    },
    onSuccess: () => {
      toast.success("Template created");
      setShowCreate(false);
      setSlug("");
      setDisplayName("");
      setDescription("");
      invalidate();
    },
    onError: () => toast.error("Failed to create template (slug may already exist)"),
  });

  const uploadMut = useMutation({
    mutationFn: async (args: { templateId: string; file: File }) => {
      const b64 = await fileToBase64(args.file);
      return uploadKycTemplateVersion(args.templateId, b64);
    },
    onSuccess: () => {
      toast.success("Version uploaded");
      invalidate();
    },
    onError: () => toast.error("Upload failed"),
  });

  const activateMut = useMutation({
    mutationFn: (args: { templateId: string; version: number }) =>
      activateKycTemplateVersion(args.templateId, args.version),
    onSuccess: () => {
      toast.success("Version activated");
      invalidate();
    },
  });

  const deactivateMut = useMutation({
    mutationFn: (args: { templateId: string; version: number }) =>
      deactivateKycTemplateVersion(args.templateId, args.version),
    onSuccess: () => {
      toast.success("Version deactivated");
      invalidate();
    },
  });

  const archiveMut = useMutation({
    mutationFn: (templateId: string) => archiveKycTemplate(templateId),
    onSuccess: () => {
      toast.success("Template archived");
      setSelected(null);
      invalidate();
    },
  });

  const templates = templatesQuery.data ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return templates;
    return templates.filter(
      (t) =>
        t.slug.toLowerCase().includes(q) ||
        t.display_name.toLowerCase().includes(q),
    );
  }, [templates, search]);

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">KYC Document Template Library</h1>
        <Button onClick={() => setShowCreate(true)}>Add Template</Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Templates</CardTitle>
          <Input
            placeholder="Search templates..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-sm"
          />
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Slug</TableHead>
                <TableHead>Display Name</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Versions</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((t) => (
                <TableRow key={t.template_id} data-testid={`tpl-row-${t.slug}`}>
                  <TableCell className="font-mono text-xs">{t.slug}</TableCell>
                  <TableCell>{t.display_name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{t.required_tier}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(t.status)}>{t.status}</Badge>
                  </TableCell>
                  <TableCell>v{t.latest_version}</TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setSelected(t)}
                    >
                      Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No templates yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Detail / versions panel */}
      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-w-2xl">
          {selected && (
            <>
              <DialogHeader>
                <DialogTitle>{selected.display_name}</DialogTitle>
              </DialogHeader>
              <div className="space-y-3">
                <div className="text-sm text-muted-foreground font-mono">
                  {selected.slug}
                </div>
                <div className="flex flex-wrap gap-1">
                  {selected.placeholder_fields.map((p) => (
                    <Badge key={p} variant="secondary" className="font-mono">
                      {"{{"}{p}{"}}"}
                    </Badge>
                  ))}
                </div>
                <div>
                  <Label className="text-xs">Upload new version</Label>
                  <Input
                    type="file"
                    accept="application/pdf"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) uploadMut.mutate({ templateId: selected.template_id, file: f });
                    }}
                  />
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Version</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selected.versions
                      .filter((v) => v.version > 0)
                      .map((v) => (
                        <TableRow key={v.version}>
                          <TableCell>v{v.version}</TableCell>
                          <TableCell>
                            <Badge variant={statusVariant(v.status)}>{v.status}</Badge>
                          </TableCell>
                          <TableCell className="space-x-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                setPreviewUrl(
                                  previewKycTemplateUrl(selected.template_id, v.version),
                                )
                              }
                            >
                              Preview
                            </Button>
                            {v.status === "active" ? (
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={() =>
                                  deactivateMut.mutate({
                                    templateId: selected.template_id,
                                    version: v.version,
                                  })
                                }
                              >
                                Deactivate
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                onClick={() =>
                                  activateMut.mutate({
                                    templateId: selected.template_id,
                                    version: v.version,
                                  })
                                }
                              >
                                Activate
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </div>
              <DialogFooter>
                <Button
                  variant="destructive"
                  onClick={() => archiveMut.mutate(selected.template_id)}
                >
                  Archive Template
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* PDF preview */}
      <Dialog open={!!previewUrl} onOpenChange={(o) => !o && setPreviewUrl(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Template Preview</DialogTitle>
          </DialogHeader>
          {previewUrl && (
            <iframe
              title="template-preview"
              src={previewUrl}
              className="h-[60vh] w-full"
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Create dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Template</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label htmlFor="tpl-slug">Slug</Label>
              <Input
                id="tpl-slug"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="aml_declaration"
              />
            </div>
            <div>
              <Label htmlFor="tpl-name">Display Name</Label>
              <Input
                id="tpl-name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Anti-Money Laundering Declaration"
              />
            </div>
            <div>
              <Label htmlFor="tpl-desc">Description</Label>
              <Textarea
                id="tpl-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div>
              <Label>Required Tier</Label>
              <Select value={tier} onValueChange={(v) => setTier(v as KycTemplateTier)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TIERS.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="tpl-placeholders">
                Placeholder fields (comma-separated; e.g. {"{{full_name}}"})
              </Label>
              <Input
                id="tpl-placeholders"
                value={placeholders}
                onChange={(e) => setPlaceholders(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!slug.trim() || !displayName.trim() || createMut.isPending}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
