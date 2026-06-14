import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, FileUp, Link2, Loader2, Upload } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";

import {
  updateCrmMetadata,
  uploadFile,
  type LinkedRecordType,
} from "@/api/endpoints/crmDocuments";
import { ApiError } from "@/api/client";
import { encodeDocPath, RECORD_TYPE_OPTIONS } from "./crmDocumentsShared";

/**
 * Upload a new file into the file manager and immediately attach CRM metadata
 * (category, description, linked record). Existing files can also be linked by
 * supplying an existing path and toggling "link existing file" instead of upload.
 */
export default function CrmDocumentUploadPage() {
  const navigate = useNavigate();
  const fileRef = useRef<HTMLInputElement>(null);

  const [mode, setMode] = useState<"upload" | "link">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [destFolder, setDestFolder] = useState("/crm-documents/");
  const [existingPath, setExistingPath] = useState("");

  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");
  const [linkType, setLinkType] = useState<LinkedRecordType | "">("");
  const [linkId, setLinkId] = useState("");

  function resolvePath(): string {
    if (mode === "link") return existingPath.trim();
    const folder = destFolder.trim().endsWith("/")
      ? destFolder.trim()
      : `${destFolder.trim()}/`;
    return `${folder}${file?.name ?? ""}`;
  }

  const submitMut = useMutation({
    mutationFn: async () => {
      const path = resolvePath();
      if (!path || (mode === "link" && !existingPath.trim())) {
        throw new ApiError(400, "A file path is required.");
      }
      if (mode === "upload") {
        if (!file) throw new ApiError(400, "Choose a file to upload.");
        await uploadFile(path, file, true);
      }
      // linked_record_type + linked_record_id are an atomic pair on the backend.
      const hasLink = linkType !== "" && linkId.trim() !== "";
      if ((linkType !== "") !== (linkId.trim() !== "")) {
        throw new ApiError(400, "Provide both a record type and a record ID, or neither.");
      }
      const meta = await updateCrmMetadata(path, {
        crm_category: category.trim() || null,
        crm_description: description.trim() || null,
        linked_record_type: hasLink ? (linkType as string) : null,
        linked_record_id: hasLink ? linkId.trim() : null,
      });
      return meta;
    },
    onSuccess: (meta) => {
      toast.success("Document saved");
      navigate(`/crm/documents/detail/${encodeDocPath(meta.path)}`);
    },
    onError: (err) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to save document";
      toast.error(msg);
    },
  });

  const canSubmit =
    mode === "upload" ? !!file && !!destFolder.trim() : !!existingPath.trim();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Upload &amp; link document"
        description="Add a document to the library and link it to a CRM record."
        actions={
          <Button asChild variant="outline">
            <Link to="/crm/documents">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Link>
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileUp className="h-4 w-4" />
            Source
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <Switch
              id="link-mode"
              checked={mode === "link"}
              onCheckedChange={(v) => setMode(v ? "link" : "upload")}
            />
            <Label htmlFor="link-mode" className="cursor-pointer">
              Link an existing file instead of uploading
            </Label>
          </div>

          {mode === "upload" ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="file">File</Label>
                <Input
                  id="file"
                  ref={fileRef}
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                {file && (
                  <p className="text-xs text-muted-foreground">
                    {file.name} ({file.size} bytes)
                  </p>
                )}
              </div>
              <div className="space-y-1">
                <Label htmlFor="folder">Destination folder</Label>
                <Input
                  id="folder"
                  value={destFolder}
                  onChange={(e) => setDestFolder(e.target.value)}
                  placeholder="/crm-documents/"
                />
                {file && (
                  <p className="text-xs text-muted-foreground">
                    Will be saved as <span className="font-mono">{resolvePath()}</span>
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-1">
              <Label htmlFor="existing-path">Existing file path</Label>
              <Input
                id="existing-path"
                value={existingPath}
                onChange={(e) => setExistingPath(e.target.value)}
                placeholder="/docs/contract.pdf"
              />
              <p className="text-xs text-muted-foreground">
                The file must already exist in your file manager.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Link2 className="h-4 w-4" />
            CRM metadata
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="category">Category</Label>
            <Input
              id="category"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              maxLength={200}
              placeholder="e.g. Contracts"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={2000}
              rows={3}
              placeholder="Optional notes about this document"
            />
            <p className="text-xs text-muted-foreground">{description.length}/2000</p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="space-y-1">
              <Label htmlFor="link-type">Linked record type</Label>
              <Select
                value={linkType}
                onValueChange={(v) => setLinkType(v as LinkedRecordType)}
              >
                <SelectTrigger id="link-type" className="w-[180px]">
                  <SelectValue placeholder="None" />
                </SelectTrigger>
                <SelectContent>
                  {RECORD_TYPE_OPTIONS.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t.charAt(0).toUpperCase() + t.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1 space-y-1">
              <Label htmlFor="link-id">Linked record ID</Label>
              <Input
                id="link-id"
                value={linkId}
                onChange={(e) => setLinkId(e.target.value)}
                maxLength={200}
                placeholder="e.g. contact_abc123"
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Provide both a record type and ID to link, or leave both empty.
          </p>
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => navigate("/crm/documents")}>
          Cancel
        </Button>
        <Button onClick={() => submitMut.mutate()} disabled={!canSubmit || submitMut.isPending}>
          {submitMut.isPending ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Upload className="mr-2 h-4 w-4" />
          )}
          Save document
        </Button>
      </div>
    </div>
  );
}
