import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Copy, GitMerge, ChevronRight } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { NotEnabledCard, isFeatureOff } from "./NotEnabledCard";
import {
  listDuplicateCandidates,
  mergeParties,
  type CctDuplicateCandidateOut,
} from "@/api/endpoints/partyCrm";

export default function PartyDedupPage() {
  const qc = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([]);

  const [mergePair, setMergePair] = useState<CctDuplicateCandidateOut | null>(null);
  const [winnerId, setWinnerId] = useState("");
  const [loserId, setLoserId] = useState("");

  const candidatesQuery = useQuery({
    queryKey: ["crm", "duplicate-candidates", cursor],
    queryFn: () => listDuplicateCandidates(cursor),
    retry: false,
  });

  const mergeMut = useMutation({
    mutationFn: () => mergeParties(winnerId.trim(), loserId.trim()),
    onSuccess: (res) => {
      toast.success(`Merged into ${res.party_id}`);
      setMergePair(null);
      void qc.invalidateQueries({ queryKey: ["crm", "duplicate-candidates"] });
      void candidatesQuery.refetch();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to merge parties"),
  });

  function openMerge(c: CctDuplicateCandidateOut) {
    setMergePair(c);
    setWinnerId(c.party_a_id);
    setLoserId(c.party_b_id);
  }

  if (isFeatureOff(candidatesQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Duplicate Contacts"
          description="SuiteCRM party-CRM dedup & merge (CCT-004/005)"
        />
        <NotEnabledCard
          feature="Duplicate Contacts"
          detail="The party_crm feature flag is off."
        />
      </div>
    );
  }

  const items = candidatesQuery.data?.items ?? [];
  const nextCursor = candidatesQuery.data?.cursor ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Duplicate Contacts"
        description="Admin sweep for likely-duplicate parties, then merge winner + loser (CCT-004/005)"
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Copy className="h-5 w-5" />
            Candidate duplicate pairs
          </CardTitle>
          <CardDescription>
            Scored by matching email/phone and fuzzy name similarity. Higher score = more likely duplicate.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {candidatesQuery.isLoading && (
            <p className="text-sm text-muted-foreground">Scanning for duplicates…</p>
          )}
          {candidatesQuery.isError && !isFeatureOff(candidatesQuery.error) && (
            <p className="text-sm text-destructive">
              {(candidatesQuery.error as Error)?.message ?? "Unable to load candidates"}
            </p>
          )}
          {!candidatesQuery.isLoading && items.length === 0 && (
            <p className="text-sm text-muted-foreground">No duplicate candidates found.</p>
          )}
          {items.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Party A</TableHead>
                  <TableHead>Party B</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Signals</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((c) => (
                  <TableRow key={`${c.party_a_id}|${c.party_b_id}`}>
                    <TableCell className="font-mono text-xs">{c.party_a_id}</TableCell>
                    <TableCell className="font-mono text-xs">{c.party_b_id}</TableCell>
                    <TableCell>
                      <Badge variant={c.score >= 0.85 ? "default" : "secondary"}>
                        {(c.score * 100).toFixed(0)}%
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {c.match_signals.map((s) => (
                          <Badge key={s} variant="outline" className="text-[10px]">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="outline" onClick={() => openMerge(c)}>
                        <GitMerge className="mr-1 h-3.5 w-3.5" />
                        Merge
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <div className="mt-4 flex justify-between">
            <Button
              variant="ghost"
              size="sm"
              disabled={cursorStack.length === 0}
              onClick={() => {
                const stack = [...cursorStack];
                const prev = stack.pop();
                setCursorStack(stack);
                setCursor(prev);
              }}
            >
              Previous
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={!nextCursor}
              onClick={() => {
                setCursorStack((s) => [...s, cursor]);
                setCursor(nextCursor ?? undefined);
              }}
            >
              Next
              <ChevronRight className="ml-1 h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog open={!!mergePair} onOpenChange={(o) => !o && setMergePair(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Merge parties</DialogTitle>
            <DialogDescription>
              The loser party is marked MERGED and its roles, relationships and contact
              mechanisms are copied onto the winner. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="winner">Winner party id (kept)</Label>
              <Input
                id="winner"
                className="font-mono text-xs"
                value={winnerId}
                onChange={(e) => setWinnerId(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="loser">Loser party id (merged away)</Label>
              <Input
                id="loser"
                className="font-mono text-xs"
                value={loserId}
                onChange={(e) => setLoserId(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setMergePair(null)}>
              Cancel
            </Button>
            <Button
              onClick={() => mergeMut.mutate()}
              disabled={mergeMut.isPending || !winnerId.trim() || !loserId.trim()}
            >
              {mergeMut.isPending ? "Merging…" : "Confirm merge"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
