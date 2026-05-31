import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listDocTemplates,
  createDocTemplate,
  updateDocTemplate,
  deleteDocTemplate,
} from "@/api/endpoints/docsAgent";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FileText, Trash2 } from "lucide-react";
import type { DocTemplate } from "@/api/types";

type DocType = "api" | "architecture" | "user_guide" | "adr" | "readme";

export default function DocTemplatesPage() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DocTemplate | null>(null);
  const [name, setName] = useState("");
  const [docType, setDocType] = useState<DocType>("api");
  const [body, setBody] = useState("");
  const [sections, setSections] = useState("");

  const { data } = useQuery({
    queryKey: ["doc-templates"],
    queryFn: () => listDocTemplates().catch(() => ({ templates: [], count: 0 })),
  });

  const resetForm = () => {
    setEditing(null);
    setName("");
    setDocType("api");
    setBody("");
    setSections("");
  };

  const saveMut = useMutation({
    mutationFn: () => {
      const requiredSections = sections
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      if (editing) {
        return updateDocTemplate(editing.template_id, {
          name,
          doc_type: docType,
          template_body: body,
          required_sections: requiredSections,
        });
      }
      return createDocTemplate({
        name,
        doc_type: docType,
        template_body: body,
        required_sections: requiredSections,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["doc-templates"] });
      setOpen(false);
      resetForm();
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteDocTemplate(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["doc-templates"] }),
  });

  const openEdit = (tmpl: DocTemplate) => {
    setEditing(tmpl);
    setName(tmpl.name);
    setDocType((tmpl.doc_type as DocType) || "api");
    setBody(tmpl.template_body);
    setSections((tmpl.required_sections || []).join("\n"));
    setOpen(true);
  };

  const templates = data?.templates ?? [];

  return (
    <div data-testid="doc-templates-page" className="space-y-6 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <FileText className="h-6 w-6" /> Documentation Templates
        </h1>
        <Dialog
          open={open}
          onOpenChange={(o) => {
            setOpen(o);
            if (!o) resetForm();
          }}
        >
          <DialogTrigger asChild>
            <Button
              onClick={() => {
                resetForm();
                setOpen(true);
              }}
            >
              New Template
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{editing ? "Edit Template" : "Create Template"}</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="tmpl-name">Name</Label>
                <Input
                  id="tmpl-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="API Endpoint Template"
                />
              </div>
              <div className="space-y-1">
                <Label>Doc Type</Label>
                <Select value={docType} onValueChange={(v) => setDocType(v as DocType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="api">api</SelectItem>
                    <SelectItem value="architecture">architecture</SelectItem>
                    <SelectItem value="user_guide">user_guide</SelectItem>
                    <SelectItem value="adr">adr</SelectItem>
                    <SelectItem value="readme">readme</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="tmpl-body">Template Body (markdown)</Label>
                <Textarea
                  id="tmpl-body"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  rows={6}
                  placeholder="# {{endpoint}}..."
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="tmpl-sections">Required Sections (one per line)</Label>
                <Textarea
                  id="tmpl-sections"
                  value={sections}
                  onChange={(e) => setSections(e.target.value)}
                  rows={3}
                />
              </div>
              <Button
                onClick={() => saveMut.mutate()}
                disabled={saveMut.isPending || !name || !body}
                className="w-full"
              >
                Save
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Sections</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {templates.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground">
                  No templates yet
                </TableCell>
              </TableRow>
            ) : (
              templates.map((tmpl) => (
                <TableRow
                  key={tmpl.template_id}
                  className="cursor-pointer"
                  onClick={() => openEdit(tmpl)}
                >
                  <TableCell className="font-medium">{tmpl.name}</TableCell>
                  <TableCell>{tmpl.doc_type}</TableCell>
                  <TableCell>{tmpl.required_sections.length}</TableCell>
                  <TableCell>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteMut.mutate(tmpl.template_id);
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
