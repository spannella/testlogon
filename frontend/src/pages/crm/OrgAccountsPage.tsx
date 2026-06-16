import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Building2,
  Search,
  Network,
  Download,
  GitBranch,
  Trash2,
} from "lucide-react";

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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { withApiBase } from "@/api/client";
import { NotEnabledCard, isFeatureOff } from "./NotEnabledCard";
import {
  patchOrgAccount,
  getOrgHierarchy,
  setParentOrg,
  removeParentOrg,
  vcardExportUrl,
  type CctOrgAccountOut,
  type CctOrgAccountUpdateIn,
} from "@/api/endpoints/partyCrm";

const INDUSTRY_CHOICES = [
  "Technology", "Finance", "Healthcare", "Education", "Retail",
  "Manufacturing", "Media", "Telecommunications", "Transportation",
  "Real Estate", "Legal", "Hospitality", "Energy", "Government",
  "Non-Profit", "Construction", "Consulting", "Agriculture", "Other",
];

function fmtCents(cents?: number | null): string {
  if (cents == null) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(cents / 100);
}

export default function OrgAccountsPage() {
  const qc = useQueryClient();
  const [idInput, setIdInput] = useState("");
  const [orgId, setOrgId] = useState<string | null>(null);

  // Business-field edit state
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [website, setWebsite] = useState("");
  const [phone, setPhone] = useState("");
  const [employeeCount, setEmployeeCount] = useState("");
  const [annualRevenueUsd, setAnnualRevenueUsd] = useState("");

  // Parent-org input
  const [parentInput, setParentInput] = useState("");

  const hierarchyQuery = useQuery({
    queryKey: ["crm", "org-hierarchy", orgId],
    queryFn: () => getOrgHierarchy(orgId!, "both"),
    enabled: !!orgId,
    retry: false,
  });

  function loadEditState(o: CctOrgAccountOut) {
    setName(o.name ?? "");
    setIndustry(o.industry ?? "");
    setWebsite(o.website ?? "");
    setPhone(o.phone ?? "");
    setEmployeeCount(o.employee_count != null ? String(o.employee_count) : "");
    setAnnualRevenueUsd(
      o.annual_revenue_cents != null ? String(o.annual_revenue_cents / 100) : "",
    );
  }

  // PATCH is the only mutating read-back of the org account, so we keep the
  // last-known org snapshot from a successful patch. The first load is a no-op
  // PATCH (empty body) which the backend treats as a touch + returns the account.
  const loadMut = useMutation({
    mutationFn: (id: string) => patchOrgAccount(id, {}),
    onSuccess: (o) => {
      setOrgId(o.party_id);
      loadEditState(o);
    },
    onError: (err: unknown) => {
      if (isFeatureOff(err)) {
        setOrgId("__feature_off__");
        return;
      }
      const msg = err instanceof Error ? err.message : "Unable to load org account";
      toast.error(msg);
    },
  });

  const orgSnapshot = loadMut.data;
  const featureOff = orgId === "__feature_off__";

  const saveMut = useMutation({
    mutationFn: () => {
      const body: CctOrgAccountUpdateIn = {
        name: name.trim() || undefined,
        industry: industry || undefined,
        website: website.trim() || undefined,
        phone: phone.trim() || undefined,
        employee_count: employeeCount.trim() ? Number(employeeCount) : undefined,
        annual_revenue_cents: annualRevenueUsd.trim()
          ? Math.round(Number(annualRevenueUsd) * 100)
          : undefined,
      };
      return patchOrgAccount(orgId!, body);
    },
    onSuccess: (o) => {
      toast.success("Org account updated");
      loadEditState(o);
      void qc.invalidateQueries({ queryKey: ["crm", "org-hierarchy", orgId] });
      // Reload the snapshot (loadMut.data) so displayed totals refresh.
      loadMut.mutate(o.party_id);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to save"),
  });

  const setParentMut = useMutation({
    mutationFn: () => setParentOrg(orgId!, parentInput.trim()),
    onSuccess: () => {
      toast.success("Parent org set");
      setParentInput("");
      void hierarchyQuery.refetch();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to set parent"),
  });

  const removeParentMut = useMutation({
    mutationFn: () => removeParentOrg(orgId!),
    onSuccess: () => {
      toast.success("Parent org removed");
      void hierarchyQuery.refetch();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to remove parent"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Org Accounts"
        description="SuiteCRM party-CRM organization accounts — business metadata & hierarchy (CCT-001/002)"
      />

      {/* Lookup */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Load an organization account</CardTitle>
          <CardDescription>
            Enter an organization party id (e.g. <code>ORG#…</code>) to inspect and edit.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              if (idInput.trim()) loadMut.mutate(idInput.trim());
            }}
          >
            <Input
              placeholder="ORG#abc123…"
              value={idInput}
              onChange={(e) => setIdInput(e.target.value)}
              aria-label="Organization party id"
            />
            <Button type="submit" disabled={loadMut.isPending || !idInput.trim()}>
              <Search className="mr-2 h-4 w-4" />
              {loadMut.isPending ? "Loading…" : "Load"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {featureOff && (
        <NotEnabledCard
          feature="Org Accounts"
          detail="The party_crm_org_accounts feature flag is off."
        />
      )}

      {!featureOff && orgSnapshot && (
        <>
          {/* Business fields */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Building2 className="h-5 w-5" />
                    {orgSnapshot.name || orgSnapshot.party_id}
                  </CardTitle>
                  <CardDescription className="font-mono text-xs">
                    {orgSnapshot.party_id}
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">{orgSnapshot.status}</Badge>
                  <Badge variant="outline">{orgSnapshot.member_count} members</Badge>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="org-name">Name</Label>
                  <Input
                    id="org-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="org-industry">Industry</Label>
                  <select
                    id="org-industry"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={industry}
                    onChange={(e) => setIndustry(e.target.value)}
                  >
                    <option value="">— none —</option>
                    {INDUSTRY_CHOICES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="org-website">Website</Label>
                  <Input
                    id="org-website"
                    placeholder="https://…"
                    value={website}
                    onChange={(e) => setWebsite(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="org-phone">Phone</Label>
                  <Input
                    id="org-phone"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="org-employees">Employee count</Label>
                  <Input
                    id="org-employees"
                    type="number"
                    min={0}
                    value={employeeCount}
                    onChange={(e) => setEmployeeCount(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="org-revenue">Annual revenue (USD)</Label>
                  <Input
                    id="org-revenue"
                    type="number"
                    min={0}
                    step="0.01"
                    placeholder="0.00"
                    value={annualRevenueUsd}
                    onChange={(e) => setAnnualRevenueUsd(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Stored: {fmtCents(orgSnapshot.annual_revenue_cents)}
                  </p>
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <Button asChild variant="outline">
                  <a href={withApiBase(vcardExportUrl(orgSnapshot.party_id))}>
                    <Download className="mr-2 h-4 w-4" />
                    Export vCard
                  </a>
                </Button>
                <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
                  {saveMut.isPending ? "Saving…" : "Save changes"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Hierarchy */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Network className="h-5 w-5" />
                Parent-org hierarchy
              </CardTitle>
              <CardDescription>
                {orgSnapshot.child_org_count} direct child org(s)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-col gap-2 sm:flex-row">
                <Input
                  placeholder="Parent ORG#… id"
                  value={parentInput}
                  onChange={(e) => setParentInput(e.target.value)}
                  aria-label="Parent org party id"
                />
                <Button
                  variant="outline"
                  onClick={() => setParentMut.mutate()}
                  disabled={setParentMut.isPending || !parentInput.trim()}
                >
                  <GitBranch className="mr-2 h-4 w-4" />
                  Set parent
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => removeParentMut.mutate()}
                  disabled={removeParentMut.isPending}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Remove parent
                </Button>
              </div>

              <Separator />

              {hierarchyQuery.isLoading && (
                <p className="text-sm text-muted-foreground">Loading hierarchy…</p>
              )}
              {hierarchyQuery.isError && (
                <p className="text-sm text-destructive">
                  {(hierarchyQuery.error as Error)?.message ?? "Unable to load hierarchy"}
                </p>
              )}
              {hierarchyQuery.data && (
                <div className="grid gap-6 sm:grid-cols-2">
                  <div>
                    <h4 className="mb-2 text-sm font-semibold">Ancestors (parent chain)</h4>
                    {hierarchyQuery.data.ancestors.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No parent org.</p>
                    ) : (
                      <ol className="space-y-1">
                        {hierarchyQuery.data.ancestors.map((r, i) => (
                          <li
                            key={r.rel_id}
                            className="flex items-center gap-2 font-mono text-xs"
                            style={{ paddingLeft: `${i * 12}px` }}
                          >
                            <GitBranch className="h-3 w-3 text-muted-foreground" />
                            {r.to_party_id}
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>
                  <div>
                    <h4 className="mb-2 text-sm font-semibold">Children</h4>
                    {hierarchyQuery.data.children.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No child orgs.</p>
                    ) : (
                      <ul className="space-y-1">
                        {hierarchyQuery.data.children.map((r) => (
                          <li key={r.rel_id} className="font-mono text-xs">
                            {r.from_party_id}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
