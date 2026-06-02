import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  addKybDirector,
  addKybDocument,
  addKybUbo,
  createKybCase,
  getKybCase,
  linkKybUbo,
  listKybCases,
  listKybDirectors,
  listKybUbos,
  removeKybDirector,
  removeKybUbo,
  setKybAddress,
  submitKybCase,
} from "@/api/endpoints/kycBusiness";
import type {
  KybAddressType,
  KybCompanyType,
  KybDirectorRole,
  KybDocumentType,
} from "@/api/types";

const COMPANY_TYPES: KybCompanyType[] = [
  "llc",
  "corp",
  "partnership",
  "sole_prop",
  "nonprofit",
  "cooperative",
  "trust",
];
const DIRECTOR_ROLES: KybDirectorRole[] = [
  "director",
  "secretary",
  "ceo",
  "cfo",
  "coo",
  "treasurer",
];
const DOCUMENT_TYPES: KybDocumentType[] = [
  "certificate_of_incorporation",
  "articles_of_association",
  "shareholder_register",
  "financial_statements",
  "board_resolution",
  "proof_of_address_registered",
  "proof_of_address_trading",
];

export default function BusinessKycPage() {
  const queryClient = useQueryClient();
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);

  const casesQuery = useQuery({
    queryKey: ["kyb", "cases"],
    queryFn: listKybCases,
  });

  const caseQuery = useQuery({
    queryKey: ["kyb", "case", activeCaseId],
    queryFn: () => getKybCase(activeCaseId as string),
    enabled: !!activeCaseId,
  });

  const ubosQuery = useQuery({
    queryKey: ["kyb", "ubos", activeCaseId],
    queryFn: () => listKybUbos(activeCaseId as string),
    enabled: !!activeCaseId,
  });

  const directorsQuery = useQuery({
    queryKey: ["kyb", "directors", activeCaseId],
    queryFn: () => listKybDirectors(activeCaseId as string),
    enabled: !!activeCaseId,
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["kyb"] });
  };

  // ── Create case form ──────────────────────────────────────────────────
  const [legalName, setLegalName] = useState("");
  const [regNumber, setRegNumber] = useState("");
  const [jurisdiction, setJurisdiction] = useState("US-DE");
  const [companyType, setCompanyType] = useState<KybCompanyType>("llc");

  const createMut = useMutation({
    mutationFn: () =>
      createKybCase({
        legal_name: legalName,
        registration_number: regNumber,
        jurisdiction,
        company_type: companyType,
      }),
    onSuccess: (res) => {
      toast.success("Business case created");
      setActiveCaseId(res.case.kyb_case_id);
      setLegalName("");
      setRegNumber("");
      refresh();
    },
    onError: () => toast.error("Failed to create business case"),
  });

  // ── UBO form ──────────────────────────────────────────────────────────
  const [uboName, setUboName] = useState("");
  const [uboPct, setUboPct] = useState("51");
  const [uboKycCaseId, setUboKycCaseId] = useState("");

  const addUboMut = useMutation({
    mutationFn: () =>
      addKybUbo(activeCaseId as string, {
        full_name: uboName,
        ownership_percentage: Number(uboPct),
        personal_kyc_case_id: uboKycCaseId || undefined,
      }),
    onSuccess: () => {
      toast.success("UBO added");
      setUboName("");
      refresh();
    },
    onError: () => toast.error("Failed to add UBO (must own > 25%)"),
  });

  const linkUboMut = useMutation({
    mutationFn: (vars: { uboId: string; kycCaseId: string }) =>
      linkKybUbo(activeCaseId as string, vars.uboId, {
        personal_kyc_case_id: vars.kycCaseId,
      }),
    onSuccess: () => {
      toast.success("UBO linked to personal KYC");
      refresh();
    },
  });

  const removeUboMut = useMutation({
    mutationFn: (uboId: string) => removeKybUbo(activeCaseId as string, uboId),
    onSuccess: refresh,
  });

  // ── Director form ─────────────────────────────────────────────────────
  const [dirName, setDirName] = useState("");
  const [dirRole, setDirRole] = useState<KybDirectorRole>("director");

  const addDirectorMut = useMutation({
    mutationFn: () =>
      addKybDirector(activeCaseId as string, { full_name: dirName, role: dirRole }),
    onSuccess: () => {
      toast.success("Director added");
      setDirName("");
      refresh();
    },
  });

  const removeDirectorMut = useMutation({
    mutationFn: (dirId: string) => removeKybDirector(activeCaseId as string, dirId),
    onSuccess: refresh,
  });

  // ── Document form ─────────────────────────────────────────────────────
  const [docType, setDocType] = useState<KybDocumentType>("certificate_of_incorporation");
  const [docNodeId, setDocNodeId] = useState("");

  const addDocMut = useMutation({
    mutationFn: () =>
      addKybDocument(activeCaseId as string, {
        document_type: docType,
        file_node_id: docNodeId || `node_${Date.now()}`,
      }),
    onSuccess: () => {
      toast.success("Document attached");
      setDocNodeId("");
      refresh();
    },
  });

  // ── Address form ──────────────────────────────────────────────────────
  const [addrType, setAddrType] = useState<KybAddressType>("registered");
  const [addrLine1, setAddrLine1] = useState("");
  const [addrCity, setAddrCity] = useState("");
  const [addrPostal, setAddrPostal] = useState("");
  const [addrCountry, setAddrCountry] = useState("US");

  const setAddrMut = useMutation({
    mutationFn: () =>
      setKybAddress(activeCaseId as string, {
        address_type: addrType,
        line1: addrLine1,
        city: addrCity,
        postal_code: addrPostal,
        country: addrCountry,
      }),
    onSuccess: () => {
      toast.success("Address saved");
      refresh();
    },
  });

  // ── Submit ────────────────────────────────────────────────────────────
  const submitMut = useMutation({
    mutationFn: () =>
      submitKybCase(activeCaseId as string, {
        expected_version: caseQuery.data?.case.version ?? 1,
      }),
    onSuccess: () => {
      toast.success("Submitted for review");
      refresh();
    },
    onError: () => toast.error("Submission failed — check requirements"),
  });

  const activeCase = caseQuery.data?.case;
  const ubos = ubosQuery.data?.ubos ?? [];
  const directors = directorsQuery.data?.directors ?? [];
  const totalPct = useMemo(
    () => ubos.reduce((acc, u) => acc + Number(u.ownership_percentage || 0), 0),
    [ubos],
  );

  return (
    <div className="container mx-auto max-w-4xl space-y-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold">Business Verification (KYB)</h1>
        <p className="text-sm text-muted-foreground">
          Verify your business / corporate account to unlock Tier 4 (Institutional).
        </p>
      </div>

      {/* Existing cases */}
      <Card>
        <CardHeader>
          <CardTitle>Your business cases</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {(casesQuery.data?.cases ?? []).map((c) => (
            <button
              key={c.kyb_case_id}
              onClick={() => setActiveCaseId(c.kyb_case_id)}
              className="flex w-full items-center justify-between rounded border p-2 text-left hover:bg-accent"
            >
              <span>{c.company.legal_name}</span>
              <Badge>{c.status}</Badge>
            </button>
          ))}
          {(casesQuery.data?.cases ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground">No business cases yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Create case */}
      <Card>
        <CardHeader>
          <CardTitle>Step 1 — Company information</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3">
          <div>
            <Label>Legal name</Label>
            <Input value={legalName} onChange={(e) => setLegalName(e.target.value)} />
          </div>
          <div>
            <Label>Registration number</Label>
            <Input value={regNumber} onChange={(e) => setRegNumber(e.target.value)} />
          </div>
          <div>
            <Label>Jurisdiction</Label>
            <Input value={jurisdiction} onChange={(e) => setJurisdiction(e.target.value)} />
          </div>
          <div>
            <Label>Company type</Label>
            <Select value={companyType} onValueChange={(v) => setCompanyType(v as KybCompanyType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {COMPANY_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="col-span-2">
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>
              Create business case
            </Button>
          </div>
        </CardContent>
      </Card>

      {activeCase && (
        <>
          <Separator />
          <p className="text-sm">
            Active case: <strong>{activeCase.kyb_case_id}</strong> · status{" "}
            <Badge>{activeCase.status}</Badge>
          </p>

          {/* UBOs */}
          <Card>
            <CardHeader>
              <CardTitle>Step 2 — Ultimate Beneficial Owners (&gt; 25%)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {ubos.map((u) => (
                <div key={u.ubo_id} className="flex items-center justify-between rounded border p-2">
                  <span>
                    {u.full_name} — {u.ownership_percentage}%
                    {u.personal_kyc_case_id ? (
                      <Badge className="ml-2">{u.personal_kyc_status ?? "linked"}</Badge>
                    ) : (
                      <Button
                        variant="link"
                        size="sm"
                        onClick={() => {
                          const id = window.prompt("Personal KYC case id");
                          if (id) linkUboMut.mutate({ uboId: u.ubo_id, kycCaseId: id });
                        }}
                      >
                        Link personal KYC
                      </Button>
                    )}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeUboMut.mutate(u.ubo_id)}
                  >
                    Remove
                  </Button>
                </div>
              ))}
              <p className="text-xs text-muted-foreground">Total ownership: {totalPct}%</p>
              <div className="grid grid-cols-3 gap-2">
                <Input
                  placeholder="Full name"
                  value={uboName}
                  onChange={(e) => setUboName(e.target.value)}
                />
                <Input
                  placeholder="Ownership %"
                  value={uboPct}
                  onChange={(e) => setUboPct(e.target.value)}
                />
                <Input
                  placeholder="Personal KYC case id (optional)"
                  value={uboKycCaseId}
                  onChange={(e) => setUboKycCaseId(e.target.value)}
                />
              </div>
              <Button onClick={() => addUboMut.mutate()} disabled={addUboMut.isPending}>
                Add UBO
              </Button>
            </CardContent>
          </Card>

          {/* Directors */}
          <Card>
            <CardHeader>
              <CardTitle>Step 3 — Directors &amp; Officers</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {directors.map((d) => (
                <div key={d.director_id} className="flex items-center justify-between rounded border p-2">
                  <span>
                    {d.full_name} — <Badge>{d.role}</Badge>
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeDirectorMut.mutate(d.director_id)}
                  >
                    Remove
                  </Button>
                </div>
              ))}
              <div className="grid grid-cols-2 gap-2">
                <Input
                  placeholder="Full name"
                  value={dirName}
                  onChange={(e) => setDirName(e.target.value)}
                />
                <Select value={dirRole} onValueChange={(v) => setDirRole(v as KybDirectorRole)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DIRECTOR_ROLES.map((r) => (
                      <SelectItem key={r} value={r}>
                        {r}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button onClick={() => addDirectorMut.mutate()} disabled={addDirectorMut.isPending}>
                Add director
              </Button>
            </CardContent>
          </Card>

          {/* Documents */}
          <Card>
            <CardHeader>
              <CardTitle>Step 4 — Corporate documents</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Documents attached: {activeCase.document_count}
              </p>
              <div className="grid grid-cols-2 gap-2">
                <Select value={docType} onValueChange={(v) => setDocType(v as KybDocumentType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DOCUMENT_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  placeholder="File node id"
                  value={docNodeId}
                  onChange={(e) => setDocNodeId(e.target.value)}
                />
              </div>
              <Button onClick={() => addDocMut.mutate()} disabled={addDocMut.isPending}>
                Attach document
              </Button>
            </CardContent>
          </Card>

          {/* Addresses */}
          <Card>
            <CardHeader>
              <CardTitle>Step 5 — Addresses</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <Select value={addrType} onValueChange={(v) => setAddrType(v as KybAddressType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="registered">registered</SelectItem>
                    <SelectItem value="trading">trading</SelectItem>
                  </SelectContent>
                </Select>
                <Input
                  placeholder="Line 1"
                  value={addrLine1}
                  onChange={(e) => setAddrLine1(e.target.value)}
                />
                <Input
                  placeholder="City"
                  value={addrCity}
                  onChange={(e) => setAddrCity(e.target.value)}
                />
                <Input
                  placeholder="Postal code"
                  value={addrPostal}
                  onChange={(e) => setAddrPostal(e.target.value)}
                />
                <Input
                  placeholder="Country"
                  value={addrCountry}
                  onChange={(e) => setAddrCountry(e.target.value)}
                />
              </div>
              <Button onClick={() => setAddrMut.mutate()} disabled={setAddrMut.isPending}>
                Save address
              </Button>
            </CardContent>
          </Card>

          {/* Submit */}
          <Card>
            <CardHeader>
              <CardTitle>Step 6 — Review &amp; submit</CardTitle>
            </CardHeader>
            <CardContent>
              <Button
                onClick={() => submitMut.mutate()}
                disabled={submitMut.isPending || activeCase.status !== "draft"}
              >
                Submit for review
              </Button>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
