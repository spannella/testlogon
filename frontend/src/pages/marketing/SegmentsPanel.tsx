import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Filter, Plus, Play, Camera, Trash2, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
  listSegments,
  createSegment,
  deleteSegment,
  evaluateSegment,
  snapshotSegment,
  listSegmentSnapshots,
  SEGMENT_ATTRIBUTES,
  SEGMENT_OPERATORS,
  type PartySegment,
  type SegmentPredicate,
} from "@/api/endpoints/marketing";
import {
  EmptyState,
  NotEnabledCard,
  errMsg,
  fmtTs,
  isNotEnabledError,
} from "./shared";

interface DraftPredicate {
  attribute: string;
  operator: string;
  value: string;
}

const NUMERIC_OPS = new Set(["gt", "gte", "lt", "lte"]);
const LIST_OPS = new Set(["in", "not_in"]);

function coerceValue(p: DraftPredicate): unknown {
  if (LIST_OPS.has(p.operator)) {
    return p.value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  if (NUMERIC_OPS.has(p.operator) || p.attribute.endsWith("_cents") || p.attribute.endsWith("_count")) {
    const n = Number(p.value);
    if (!Number.isNaN(n) && p.value.trim() !== "") return n;
  }
  if (p.value === "true") return true;
  if (p.value === "false") return false;
  return p.value;
}

export function SegmentsPanel() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [predicates, setPredicates] = useState<DraftPredicate[]>([
    { attribute: SEGMENT_ATTRIBUTES[0], operator: "eq", value: "" },
  ]);
  const [evalResults, setEvalResults] = useState<
    { party_id: string; opted_out: boolean }[] | null
  >(null);

  const segsQ = useQuery({
    queryKey: ["mkt", "segments"],
    queryFn: () => listSegments(),
    retry: false,
  });

  const snapsQ = useQuery({
    queryKey: ["mkt", "segment", selectedId, "snapshots"],
    queryFn: () => listSegmentSnapshots(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createSegment({
        name: name.trim(),
        description: desc.trim() || undefined,
        predicates: predicates.map<SegmentPredicate>((p) => ({
          attribute: p.attribute,
          operator: p.operator,
          value: coerceValue(p),
        })),
      }),
    onSuccess: (s) => {
      toast.success("Segment created");
      setCreateOpen(false);
      setName("");
      setDesc("");
      setPredicates([{ attribute: SEGMENT_ATTRIBUTES[0], operator: "eq", value: "" }]);
      setSelectedId(s.segment_id);
      void qc.invalidateQueries({ queryKey: ["mkt", "segments"] });
    },
    onError: (e) => toast.error(errMsg(e, "Unable to create segment")),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteSegment(id),
    onSuccess: () => {
      toast.success("Segment deleted");
      setSelectedId(null);
      setEvalResults(null);
      void qc.invalidateQueries({ queryKey: ["mkt", "segments"] });
    },
    onError: (e) => toast.error(errMsg(e, "Delete failed")),
  });

  const evalMut = useMutation({
    mutationFn: (id: string) => evaluateSegment(id),
    onSuccess: (rows) => {
      setEvalResults(rows);
      toast.success(`${rows.length} match(es)`);
    },
    onError: (e) => toast.error(errMsg(e, "Evaluate failed")),
  });

  const snapMut = useMutation({
    mutationFn: (id: string) => snapshotSegment(id),
    onSuccess: (s) => {
      toast.success(`Snapshot ${s.snap_id} (${s.party_count} parties)`);
      void qc.invalidateQueries({ queryKey: ["mkt", "segment", selectedId, "snapshots"] });
    },
    onError: (e) => toast.error(errMsg(e, "Snapshot failed")),
  });

  if (isNotEnabledError(segsQ.error)) {
    return <NotEnabledCard what="Party segments" />;
  }

  const segments = segsQ.data ?? [];
  const selected = segments.find((s) => s.segment_id === selectedId) ?? null;
  const snapshots = snapsQ.data ?? [];

  function updatePred(i: number, patch: Partial<DraftPredicate>) {
    setPredicates((cur) => cur.map((p, idx) => (idx === i ? { ...p, ...patch } : p)));
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Filter className="h-4 w-4" /> Party segments
            </CardTitle>
            <CardDescription>{segments.length} segment(s)</CardDescription>
          </div>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-3.5 w-3.5" /> New
          </Button>
        </CardHeader>
        <CardContent>
          {segsQ.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : segments.length === 0 ? (
            <EmptyState title="No segments" hint="Build a predicate-based segment." />
          ) : (
            <div className="space-y-1">
              {segments.map((s: PartySegment) => (
                <button
                  key={s.segment_id}
                  data-testid="segment-row"
                  className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm ${
                    selectedId === s.segment_id ? "bg-muted" : ""
                  }`}
                  onClick={() => {
                    setSelectedId(s.segment_id);
                    setEvalResults(null);
                  }}
                >
                  <span className="font-medium">{s.name}</span>
                  <Badge variant="secondary">{s.predicates.length} rule(s)</Badge>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>{selected ? selected.name : "Details"}</CardTitle>
            <CardDescription>{selected?.description || "Select a segment"}</CardDescription>
          </div>
          {selected && (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={evalMut.isPending}
                onClick={() => evalMut.mutate(selected.segment_id)}
              >
                <Play className="mr-1 h-3.5 w-3.5" /> Evaluate
              </Button>
              <Button
                size="sm"
                disabled={snapMut.isPending}
                onClick={() => snapMut.mutate(selected.segment_id)}
              >
                <Camera className="mr-1 h-3.5 w-3.5" /> Snapshot
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={deleteMut.isPending}
                onClick={() => deleteMut.mutate(selected.segment_id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          {!selected ? (
            <EmptyState title="No segment selected" />
          ) : (
            <>
              <div className="space-y-1">
                <Label className="text-xs uppercase text-muted-foreground">Predicates</Label>
                <div className="space-y-1">
                  {selected.predicates.map((p, i) => (
                    <div key={i} className="rounded-md border px-2 py-1 text-xs">
                      <span className="font-mono">{p.attribute}</span>{" "}
                      <span className="text-muted-foreground">{p.operator}</span>{" "}
                      <span className="font-mono">{JSON.stringify(p.value)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {evalResults && (
                <>
                  <Separator />
                  <div className="space-y-1">
                    <Label className="text-xs uppercase text-muted-foreground">
                      Evaluation — {evalResults.length} match(es)
                    </Label>
                    <div className="max-h-48 space-y-1 overflow-auto">
                      {evalResults.length === 0 ? (
                        <p className="text-xs text-muted-foreground">No matching parties.</p>
                      ) : (
                        evalResults.map((r) => (
                          <div
                            key={r.party_id}
                            className="flex items-center justify-between rounded border px-2 py-1 text-xs"
                          >
                            <span className="font-mono">{r.party_id}</span>
                            {r.opted_out && <Badge variant="destructive">opted-out</Badge>}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </>
              )}

              <Separator />
              <div className="space-y-1">
                <Label className="text-xs uppercase text-muted-foreground">Snapshots</Label>
                {snapsQ.isLoading ? (
                  <Skeleton className="h-16 w-full" />
                ) : snapshots.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No snapshots yet.</p>
                ) : (
                  <div className="space-y-1">
                    {snapshots.map((s) => (
                      <div
                        key={s.snap_id}
                        className="flex items-center justify-between rounded border px-2 py-1 text-xs"
                      >
                        <span className="font-mono">{s.snap_id}</span>
                        <span>
                          {s.party_count} parties · {fmtTs(s.snap_ts)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Create dialog with predicate builder */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>New segment</DialogTitle>
            <DialogDescription>
              All predicates must match (AND). Use comma-separated values for in/not_in.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="seg-name">Name</Label>
                <Input id="seg-name" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="seg-desc">Description</Label>
                <Input id="seg-desc" value={desc} onChange={(e) => setDesc(e.target.value)} />
              </div>
            </div>

            <Label className="text-xs uppercase text-muted-foreground">Predicates</Label>
            <div className="space-y-2">
              {predicates.map((p, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Select value={p.attribute} onValueChange={(v) => updatePred(i, { attribute: v })}>
                    <SelectTrigger className="w-[180px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SEGMENT_ATTRIBUTES.map((a) => (
                        <SelectItem key={a} value={a}>
                          {a}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={p.operator} onValueChange={(v) => updatePred(i, { operator: v })}>
                    <SelectTrigger className="w-[100px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SEGMENT_OPERATORS.map((o) => (
                        <SelectItem key={o} value={o}>
                          {o}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    placeholder="value"
                    value={p.value}
                    onChange={(e) => updatePred(i, { value: e.target.value })}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={predicates.length === 1}
                    onClick={() => setPredicates((cur) => cur.filter((_, idx) => idx !== i))}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() =>
                setPredicates((cur) => [
                  ...cur,
                  { attribute: SEGMENT_ATTRIBUTES[0], operator: "eq", value: "" },
                ])
              }
            >
              <Plus className="mr-1 h-3.5 w-3.5" /> Add predicate
            </Button>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!name.trim() || createMut.isPending || predicates.some((p) => !p.value.trim())}
              onClick={() => createMut.mutate()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
