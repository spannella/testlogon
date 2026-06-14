/**
 * SuiteCRM Workflow (WFL) — drip sequence management.
 * Admin-oriented. Route: /crm/workflow/drip-sequences.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, Mail, Pencil, Plus, Trash2 } from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  createDripSequence,
  deleteDripSequence,
  listDripSequences,
  updateDripSequence,
  type DripSequenceOut,
  type DripStageIn,
} from "@/api/endpoints/crmWorkflow";
import { fmtTs, isFlagOffError, NotEnabledCard } from "./workflowShared";

interface EditableStage {
  stage_number: number;
  delay_hours: string;
  template_id: string;
  to_field: string;
}

function stagesFromSeq(seq?: DripSequenceOut | null): EditableStage[] {
  if (!seq) return [{ stage_number: 1, delay_hours: "0", template_id: "", to_field: "email" }];
  return (seq.stages ?? []).map((s, i) => ({
    stage_number: Number(s["stage_number"] ?? i + 1),
    delay_hours: String(s["delay_hours"] ?? 0),
    template_id: String(s["template_id"] ?? ""),
    to_field: String(s["to_field"] ?? "email"),
  }));
}

function SequenceEditorDialog({
  open,
  onOpenChange,
  sequence,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  sequence?: DripSequenceOut | null;
}) {
  const qc = useQueryClient();
  const isEdit = !!sequence;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [stages, setStages] = useState<EditableStage[]>(stagesFromSeq(null));

  useEffect(() => {
    if (!open) return;
    setName(sequence?.name ?? "");
    setDescription(sequence?.description ?? "");
    setStages(stagesFromSeq(sequence));
  }, [open, sequence]);

  const build = (): DripStageIn[] | null => {
    if (stages.length === 0) {
      toast.error("Add at least one stage");
      return null;
    }
    const out: DripStageIn[] = [];
    for (let i = 0; i < stages.length; i++) {
      const s = stages[i]!;
      if (!s.template_id.trim()) {
        toast.error(`Stage ${i + 1}: template ID is required`);
        return null;
      }
      if (!s.to_field.trim()) {
        toast.error(`Stage ${i + 1}: recipient field is required`);
        return null;
      }
      const delay = Number(s.delay_hours);
      if (!Number.isFinite(delay) || delay < 0) {
        toast.error(`Stage ${i + 1}: delay must be 0 or more hours`);
        return null;
      }
      out.push({
        stage_number: i + 1,
        delay_hours: Math.floor(delay),
        template_id: s.template_id.trim(),
        to_field: s.to_field.trim(),
      });
    }
    return out;
  };

  const createMut = useMutation({
    mutationFn: () => {
      const built = build();
      if (!built) return Promise.reject(new Error("validation"));
      return createDripSequence({
        name: name.trim(),
        description: description.trim(),
        stages: built,
      });
    },
    onSuccess: () => {
      toast.success("Drip sequence created");
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "drip-sequences"] });
      onOpenChange(false);
    },
    onError: (err: unknown) => {
      if (err instanceof Error && err.message === "validation") return;
      toast.error(err instanceof Error ? err.message : "Unable to create sequence");
    },
  });

  const updateMut = useMutation({
    mutationFn: () => {
      const built = build();
      if (!built) return Promise.reject(new Error("validation"));
      return updateDripSequence(sequence!.sequence_id, {
        name: name.trim(),
        description: description.trim(),
        stages: built,
      });
    },
    onSuccess: () => {
      toast.success("Drip sequence updated");
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "drip-sequences"] });
      onOpenChange(false);
    },
    onError: (err: unknown) => {
      if (err instanceof Error && err.message === "validation") return;
      toast.error(err instanceof Error ? err.message : "Unable to update sequence");
    },
  });

  const pending = createMut.isPending || updateMut.isPending;

  const addStage = () =>
    setStages((s) => [
      ...s,
      {
        stage_number: s.length + 1,
        delay_hours: "24",
        template_id: "",
        to_field: "email",
      },
    ]);
  const removeStage = (idx: number) =>
    setStages((s) => s.filter((_, i) => i !== idx));
  const patchStage = (idx: number, patch: Partial<EditableStage>) =>
    setStages((s) => s.map((st, i) => (i === idx ? { ...st, ...patch } : st)));

  const submit = () => {
    if (!name.trim()) {
      toast.error("Sequence name is required");
      return;
    }
    if (isEdit) updateMut.mutate();
    else createMut.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit drip sequence" : "New drip sequence"}</DialogTitle>
          <DialogDescription>
            A drip sequence sends a series of templated emails on a delay, stage
            by stage.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="seq-name">Name</Label>
            <Input
              id="seq-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="New lead nurture"
              maxLength={200}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="seq-desc">Description</Label>
            <Textarea
              id="seq-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">Stages</h3>
              <Button type="button" size="sm" variant="outline" onClick={addStage}>
                <Plus className="mr-1 h-4 w-4" /> Add stage
              </Button>
            </div>
            {stages.map((s, idx) => (
              <div key={idx} className="space-y-2 rounded-md border p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Stage {idx + 1}</span>
                  {stages.length > 1 && (
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      onClick={() => removeStage(idx)}
                      aria-label="Remove stage"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <div className="space-y-1">
                    <Label className="text-xs">Delay (hours)</Label>
                    <Input
                      type="number"
                      min={0}
                      value={s.delay_hours}
                      onChange={(e) => patchStage(idx, { delay_hours: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Template ID</Label>
                    <Input
                      value={s.template_id}
                      onChange={(e) => patchStage(idx, { template_id: e.target.value })}
                      placeholder="welcome_email"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Recipient field</Label>
                    <Input
                      value={s.to_field}
                      onChange={(e) => patchStage(idx, { to_field: e.target.value })}
                      placeholder="email"
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={pending}>
            {pending ? "Saving…" : isEdit ? "Save changes" : "Create sequence"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function WorkflowDripSequencesPage() {
  const qc = useQueryClient();

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DripSequenceOut | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DripSequenceOut | null>(null);

  const seqQuery = useQuery({
    queryKey: ["crm-workflow", "drip-sequences"],
    queryFn: () => listDripSequences({ limit: 100 }),
    retry: (count, err) => !isFlagOffError(err) && count < 1,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteDripSequence(id),
    onSuccess: () => {
      toast.success("Drip sequence deleted");
      setDeleteTarget(null);
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "drip-sequences"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to delete sequence"),
  });

  const sequences = seqQuery.data?.sequences ?? [];

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };
  const openEdit = (seq: DripSequenceOut) => {
    setEditing(seq);
    setEditorOpen(true);
  };

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Drip sequences"
        description="Multi-stage email campaigns triggered by workflow rules."
        actions={
          <div className="flex items-center gap-2">
            <Button asChild variant="outline">
              <Link to="/crm/workflow">
                <ArrowLeft className="mr-1 h-4 w-4" /> Rules
              </Link>
            </Button>
            <Button onClick={openCreate}>
              <Plus className="mr-1 h-4 w-4" /> New sequence
            </Button>
          </div>
        }
      />

      {seqQuery.isError ? (
        <NotEnabledCard error={seqQuery.error} />
      ) : (
        <Card>
          <CardContent className="pt-6">
            {seqQuery.isLoading ? (
              <div className="space-y-2">
                {[0, 1, 2].map((i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : sequences.length === 0 ? (
              <div className="rounded-md border border-dashed p-10 text-center">
                <Mail className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
                <p className="text-sm font-medium">No drip sequences yet</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Create a sequence and reference it from a workflow action.
                </p>
                <Button className="mt-4" onClick={openCreate}>
                  <Plus className="mr-1 h-4 w-4" /> New sequence
                </Button>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead className="text-center">Stages</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="text-right">Manage</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sequences.map((seq) => (
                    <TableRow key={seq.sequence_id}>
                      <TableCell>
                        <div className="font-medium">{seq.name}</div>
                        {seq.description && (
                          <div className="max-w-md truncate text-xs text-muted-foreground">
                            {seq.description}
                          </div>
                        )}
                        <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                          {seq.sequence_id}
                        </div>
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge variant="outline">{seq.stages.length}</Badge>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {fmtTs(seq.updated_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => openEdit(seq)}
                            aria-label="Edit sequence"
                            title="Edit"
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => setDeleteTarget(seq)}
                            aria-label="Delete sequence"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <SequenceEditorDialog
        open={editorOpen}
        onOpenChange={setEditorOpen}
        sequence={editing}
      />

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(v) => !v && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete drip sequence?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes “{deleteTarget?.name}”. Workflow actions
              referencing it will stop enrolling new records.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMut.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleteMut.isPending}
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.sequence_id)}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
