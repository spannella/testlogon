import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { NotificationTemplate, NotificationTemplatePreview } from "@/api/types";
import {
  listNotificationTemplates,
  previewNotificationTemplate,
  testSendNotificationTemplate,
  updateNotificationTemplate,
} from "@/api/endpoints/adminMessagingDashboards";

function sampleVarsFor(tpl: NotificationTemplate): Record<string, string> {
  const out: Record<string, string> = {};
  for (const v of tpl.variables) out[v] = `[${v}]`;
  return out;
}

export default function MessagingTemplatesPanel() {
  const qc = useQueryClient();
  const [editTpl, setEditTpl] = useState<NotificationTemplate | null>(null);
  const [editSubject, setEditSubject] = useState("");
  const [editBody, setEditBody] = useState("");
  const [previewTpl, setPreviewTpl] = useState<NotificationTemplate | null>(null);
  const [previewData, setPreviewData] = useState<NotificationTemplatePreview | null>(null);
  const [testTpl, setTestTpl] = useState<NotificationTemplate | null>(null);
  const [testRecipient, setTestRecipient] = useState("");

  const templates = useQuery({
    queryKey: ["admin-templates"],
    queryFn: () => listNotificationTemplates(),
    staleTime: 120_000,
  });

  const saveMut = useMutation({
    mutationFn: () =>
      updateNotificationTemplate(editTpl!.template_id, {
        subject: editSubject,
        body: editBody,
      }),
    onSuccess: () => {
      toast.success("Template saved");
      setEditTpl(null);
      qc.invalidateQueries({ queryKey: ["admin-templates"] });
    },
    onError: () => toast.error("Failed to save template"),
  });

  const previewMut = useMutation({
    mutationFn: (tpl: NotificationTemplate) =>
      previewNotificationTemplate(tpl.template_id, sampleVarsFor(tpl)),
    onSuccess: (data) => setPreviewData(data),
    onError: () => toast.error("Failed to preview template"),
  });

  const testMut = useMutation({
    mutationFn: () =>
      testSendNotificationTemplate(
        testTpl!.template_id,
        testRecipient,
        sampleVarsFor(testTpl!),
      ),
    onSuccess: () => {
      toast.success("Test notification sent");
      setTestTpl(null);
      setTestRecipient("");
    },
    onError: () => toast.error("Failed to send test notification"),
  });

  function openEdit(tpl: NotificationTemplate) {
    setEditTpl(tpl);
    setEditSubject(tpl.subject ?? "");
    setEditBody(tpl.body ?? "");
  }

  function openPreview(tpl: NotificationTemplate) {
    setPreviewTpl(tpl);
    setPreviewData(null);
    previewMut.mutate(tpl);
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Notification Templates</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Channel</TableHead>
                <TableHead>Subject</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(templates.data ?? []).map((tpl) => (
                <TableRow key={tpl.template_id} data-testid={`template-row-${tpl.template_id}`}>
                  <TableCell>{tpl.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{tpl.channel}</Badge>
                  </TableCell>
                  <TableCell className="max-w-[260px] truncate">{tpl.subject ?? "—"}</TableCell>
                  <TableCell className="space-x-2 whitespace-nowrap">
                    <Button size="sm" variant="outline" onClick={() => openEdit(tpl)}>
                      Edit
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => openPreview(tpl)}>
                      Preview
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        setTestTpl(tpl);
                        setTestRecipient("");
                      }}
                    >
                      Test send
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Edit dialog */}
      <Dialog open={!!editTpl} onOpenChange={(o) => !o && setEditTpl(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit {editTpl?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            {editTpl?.channel === "email" && (
              <div className="space-y-1">
                <Label htmlFor="tpl-subject">Subject</Label>
                <Input
                  id="tpl-subject"
                  value={editSubject}
                  onChange={(e) => setEditSubject(e.target.value)}
                />
              </div>
            )}
            <div className="space-y-1">
              <Label htmlFor="tpl-body">Body</Label>
              <Textarea
                id="tpl-body"
                rows={8}
                value={editBody}
                onChange={(e) => setEditBody(e.target.value)}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Variables: {editTpl?.variables.map((v) => `{{${v}}}`).join(", ") || "none"}
            </p>
          </div>
          <DialogFooter>
            <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Preview dialog */}
      <Dialog open={!!previewTpl} onOpenChange={(o) => !o && setPreviewTpl(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Preview {previewTpl?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            {previewData?.rendered_subject != null && (
              <div>
                <div className="text-xs text-muted-foreground">Subject</div>
                <div className="font-medium">{previewData.rendered_subject}</div>
              </div>
            )}
            <div>
              <div className="text-xs text-muted-foreground">Body</div>
              <pre className="whitespace-pre-wrap rounded border p-2 text-sm">
                {previewData?.rendered_body ?? "…"}
              </pre>
            </div>
            {previewData && previewData.missing_vars.length > 0 && (
              <p className="text-xs text-amber-600">
                Missing vars: {previewData.missing_vars.join(", ")}
              </p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Test send dialog */}
      <Dialog open={!!testTpl} onOpenChange={(o) => !o && setTestTpl(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test send {testTpl?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-1">
            <Label htmlFor="tpl-test-recipient">Recipient</Label>
            <Input
              id="tpl-test-recipient"
              value={testRecipient}
              onChange={(e) => setTestRecipient(e.target.value)}
              placeholder={testTpl?.channel === "email" ? "admin@test.local" : "+15551234567"}
            />
          </div>
          <DialogFooter>
            <Button
              onClick={() => testMut.mutate()}
              disabled={!testRecipient || testMut.isPending}
            >
              Send test
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
