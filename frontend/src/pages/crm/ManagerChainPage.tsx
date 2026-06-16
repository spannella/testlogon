import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Users, Search, UserCog, Trash2, ArrowDown } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { NotEnabledCard, isFeatureOff } from "./NotEnabledCard";
import {
  getReportsTo,
  setManager,
  removeManager,
} from "@/api/endpoints/partyCrm";

export default function ManagerChainPage() {
  const [idInput, setIdInput] = useState("");
  const [partyId, setPartyId] = useState<string | null>(null);
  const [managerInput, setManagerInput] = useState("");

  const chainQuery = useQuery({
    queryKey: ["crm", "manager-chain", partyId],
    queryFn: () => getReportsTo(partyId!, "manager_chain"),
    enabled: !!partyId,
    retry: false,
  });

  const reportsQuery = useQuery({
    queryKey: ["crm", "direct-reports", partyId],
    queryFn: () => getReportsTo(partyId!, "reports"),
    enabled: !!partyId,
    retry: false,
  });

  const setMgrMut = useMutation({
    mutationFn: () => setManager(partyId!, managerInput.trim()),
    onSuccess: () => {
      toast.success("Manager set");
      setManagerInput("");
      void chainQuery.refetch();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to set manager"),
  });

  const removeMgrMut = useMutation({
    mutationFn: () => removeManager(partyId!),
    onSuccess: () => {
      toast.success("Manager removed");
      void chainQuery.refetch();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to remove manager"),
  });

  const featureOff =
    isFeatureOff(chainQuery.error) || isFeatureOff(reportsQuery.error);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports-To Chain"
        description="SuiteCRM party-CRM manager chains (CCT-003) — set a person's manager and view the org chart upward and downward"
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Load a person</CardTitle>
          <CardDescription>Enter a person party id to inspect the reporting chain.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              if (idInput.trim()) setPartyId(idInput.trim());
            }}
          >
            <Input
              placeholder="party id…"
              value={idInput}
              onChange={(e) => setIdInput(e.target.value)}
              aria-label="Person party id"
            />
            <Button type="submit" disabled={!idInput.trim()}>
              <Search className="mr-2 h-4 w-4" />
              Load
            </Button>
          </form>
        </CardContent>
      </Card>

      {featureOff && (
        <NotEnabledCard
          feature="Reports-To Chain"
          detail="The party_crm feature flag is off."
        />
      )}

      {!featureOff && partyId && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <UserCog className="h-5 w-5" />
                Manager
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-col gap-2 sm:flex-row">
                <Input
                  placeholder="Manager party id…"
                  value={managerInput}
                  onChange={(e) => setManagerInput(e.target.value)}
                  aria-label="Manager party id"
                />
                <Button
                  variant="outline"
                  onClick={() => setMgrMut.mutate()}
                  disabled={setMgrMut.isPending || !managerInput.trim()}
                >
                  Set manager
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => removeMgrMut.mutate()}
                  disabled={removeMgrMut.isPending}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Remove
                </Button>
              </div>

              <Separator />

              <div>
                <h4 className="mb-2 text-sm font-semibold">Manager chain (upward)</h4>
                {chainQuery.isLoading && (
                  <p className="text-sm text-muted-foreground">Loading…</p>
                )}
                {chainQuery.data && chainQuery.data.chain.length === 0 && (
                  <p className="text-sm text-muted-foreground">No manager set.</p>
                )}
                {chainQuery.data && chainQuery.data.chain.length > 0 && (
                  <ol className="space-y-1">
                    <li className="flex items-center gap-2 font-mono text-xs font-semibold">
                      {partyId}
                    </li>
                    {chainQuery.data.chain.map((r, i) => (
                      <li
                        key={r.rel_id}
                        className="flex items-center gap-2 font-mono text-xs"
                        style={{ paddingLeft: `${(i + 1) * 14}px` }}
                      >
                        <ArrowDown className="h-3 w-3 rotate-180 text-muted-foreground" />
                        {r.to_party_id}
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Users className="h-5 w-5" />
                Direct reports (downward)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {reportsQuery.isLoading && (
                <p className="text-sm text-muted-foreground">Loading…</p>
              )}
              {reportsQuery.data && reportsQuery.data.chain.length === 0 && (
                <p className="text-sm text-muted-foreground">No direct reports.</p>
              )}
              {reportsQuery.data && reportsQuery.data.chain.length > 0 && (
                <ul className="space-y-1">
                  {reportsQuery.data.chain.map((r) => (
                    <li key={r.rel_id} className="font-mono text-xs">
                      {r.from_party_id}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
