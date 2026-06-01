import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Loader2,
  ScanLine,
  Globe,
  CreditCard,
  Car,
  Home,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  listKycIdScans,
  scanKycIdDocument,
} from "@/api/endpoints/kycIdScanner";
import type {
  KycIdScannerDocumentType,
  KycIdScannerFileType,
  KycIdScannerScanOut,
} from "@/api/types";

const DOC_TYPES: { value: KycIdScannerDocumentType; label: string; icon: typeof Globe }[] = [
  { value: "passport", label: "Passport", icon: Globe },
  { value: "national_id_card", label: "National ID", icon: CreditCard },
  { value: "driving_license", label: "Driving License", icon: Car },
  { value: "residence_permit", label: "Residence Permit", icon: Home },
];

function statusVariant(status: string) {
  if (status === "matched" || status === "approved") return "default" as const;
  if (status === "flagged") return "secondary" as const;
  return "destructive" as const;
}

function ChecksumBadge({ label, ok }: { label: string; ok?: boolean | null }) {
  if (ok === null || ok === undefined) return null;
  return (
    <Badge
      variant={ok ? "default" : "destructive"}
      data-testid={`kyc-scan-checksum-${label}`}
    >
      {ok ? <CheckCircle2 className="mr-1 h-3 w-3" /> : <XCircle className="mr-1 h-3 w-3" />}
      {label}
    </Badge>
  );
}

function ExtractionResults({ scan }: { scan: KycIdScannerScanOut }) {
  const ex = scan.extraction;
  const checks = ex.checksums;
  const expiry = scan.expiry_check;
  const cross = scan.cross_reference;
  return (
    <Card data-testid="kyc-scan-result" data-scan-id={scan.scan_id}>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div>
          <CardTitle className="text-base">{scan.document_type}</CardTitle>
          <CardDescription>{scan.file_type}</CardDescription>
        </div>
        <Badge variant={statusVariant(scan.status)} data-testid="kyc-scan-status">
          {scan.status}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        {ex.error ? (
          <div className="flex items-center gap-2 text-sm text-destructive" data-testid="kyc-scan-error">
            <AlertTriangle className="h-4 w-4" />
            Extraction error: {ex.error}
          </div>
        ) : (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm" data-testid="kyc-scan-fields">
            <dt className="text-muted-foreground">Surname</dt>
            <dd className="font-medium">{ex.surname ?? "—"}</dd>
            <dt className="text-muted-foreground">Given names</dt>
            <dd className="font-medium">{ex.given_names ?? "—"}</dd>
            <dt className="text-muted-foreground">Document number</dt>
            <dd className="font-medium">{ex.document_number ?? "—"}</dd>
            <dt className="text-muted-foreground">Nationality</dt>
            <dd className="font-medium">{ex.nationality ?? "—"}</dd>
            <dt className="text-muted-foreground">Date of birth</dt>
            <dd className="font-medium">{ex.date_of_birth ?? "—"}</dd>
            <dt className="text-muted-foreground">Sex</dt>
            <dd className="font-medium">{ex.sex ?? "—"}</dd>
            <dt className="text-muted-foreground">Expiry date</dt>
            <dd className="font-medium">{ex.expiry_date ?? "—"}</dd>
            <dt className="text-muted-foreground">Issuing state</dt>
            <dd className="font-medium">{ex.issuing_state ?? "—"}</dd>
          </dl>
        )}

        {checks && (
          <div className="flex flex-wrap gap-1" data-testid="kyc-scan-checksums">
            <ChecksumBadge label="doc_number" ok={checks.document_number} />
            <ChecksumBadge label="dob" ok={checks.date_of_birth} />
            <ChecksumBadge label="expiry" ok={checks.expiry_date} />
            <ChecksumBadge label="optional" ok={checks.optional_data} />
            <ChecksumBadge label="composite" ok={checks.composite} />
          </div>
        )}

        <div
          className={
            "rounded-md border p-2 text-sm " +
            (expiry.status === "expired"
              ? "border-destructive text-destructive"
              : expiry.status === "expiring_soon"
                ? "border-yellow-500 text-yellow-700"
                : "border-muted text-muted-foreground")
          }
          data-testid="kyc-scan-expiry"
          data-expiry-status={expiry.status}
        >
          {expiry.message}
        </div>

        {cross && (
          <div className="space-y-1 text-sm" data-testid="kyc-scan-crossref">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Profile match score</span>
              <span className="font-medium">{cross.match_score}%</span>
            </div>
            {Object.keys(cross.mismatches).length > 0 && (
              <div className="text-destructive" data-testid="kyc-scan-mismatches">
                Mismatched: {Object.keys(cross.mismatches).join(", ")}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function KycIdScannerPage() {
  const queryClient = useQueryClient();
  const [caseId, setCaseId] = useState("");
  const [docType, setDocType] = useState<KycIdScannerDocumentType>("passport");
  const [fileType, setFileType] = useState<KycIdScannerFileType>("id_front");
  const [mrzText, setMrzText] = useState("");
  const [lastScan, setLastScan] = useState<KycIdScannerScanOut | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["kyc-id-scans", caseId],
    queryFn: () => listKycIdScans(caseId),
    enabled: caseId.trim().length > 0,
  });

  const scan = useMutation({
    mutationFn: () => {
      const lines = mrzText
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      return scanKycIdDocument(caseId.trim(), {
        document_type: docType,
        file_type: fileType,
        mrz_lines: lines.length > 0 ? lines : null,
      });
    },
    onSuccess: (result) => {
      setLastScan(result);
      toast.success(`Scan ${result.status}`);
      queryClient.invalidateQueries({ queryKey: ["kyc-id-scans", caseId] });
    },
    onError: () => toast.error("Scan failed"),
  });

  const scans = data?.scans ?? [];
  const selectedDoc = DOC_TYPES.find((d) => d.value === docType);

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4">
      <div className="flex items-center gap-2">
        <ScanLine className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Passport / National-ID Scanner</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Scan a document</CardTitle>
          <CardDescription>
            Scan an uploaded passport or national-ID image to extract and validate
            its machine-readable zone (MRZ).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <label className="text-sm text-muted-foreground">KYC case ID</label>
            <Input
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              placeholder="kyc_..."
              data-testid="kyc-scan-case-id"
            />
          </div>

          <div className="flex flex-wrap gap-2" data-testid="kyc-scan-doc-types">
            {DOC_TYPES.map(({ value, label, icon: Icon }) => (
              <Button
                key={value}
                type="button"
                size="sm"
                variant={docType === value ? "default" : "outline"}
                onClick={() => setDocType(value)}
                data-testid={`kyc-scan-doctype-${value}`}
              >
                <Icon className="mr-1 h-4 w-4" />
                {label}
              </Button>
            ))}
          </div>

          <div className="space-y-1">
            <label className="text-sm text-muted-foreground">Side</label>
            <Select value={fileType} onValueChange={(v) => setFileType(v as KycIdScannerFileType)}>
              <SelectTrigger data-testid="kyc-scan-side-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="id_front">Front</SelectItem>
                <SelectItem value="id_back">Back</SelectItem>
              </SelectContent>
            </Select>
            {selectedDoc && (
              <p className="text-xs text-muted-foreground">
                {docType === "passport"
                  ? "Front only"
                  : "Front and back required"}
              </p>
            )}
          </div>

          <div className="space-y-1">
            <label className="text-sm text-muted-foreground">
              MRZ lines (optional, for testing)
            </label>
            <Textarea
              value={mrzText}
              onChange={(e) => setMrzText(e.target.value)}
              placeholder={"Paste 2 lines for passport, 3 for ID card"}
              rows={3}
              data-testid="kyc-scan-mrz"
            />
          </div>

          <Button
            onClick={() => scan.mutate()}
            disabled={!caseId.trim() || scan.isPending}
            data-testid="kyc-scan-submit"
          >
            {scan.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Scan Document
          </Button>
        </CardContent>
      </Card>

      {lastScan && <ExtractionResults scan={lastScan} />}

      <div className="space-y-3">
        <h2 className="text-lg font-medium">Previous scans</h2>
        {!caseId.trim() ? (
          <p className="text-sm text-muted-foreground">Enter a case ID to view scans.</p>
        ) : isLoading ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : scans.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="kyc-scan-empty">
            No scans for this case yet.
          </p>
        ) : (
          <div className="space-y-2">
            {scans.map((s) => (
              <Card key={s.scan_id} data-testid="kyc-scan-summary" data-scan-id={s.scan_id}>
                <CardContent className="flex items-center justify-between gap-2 p-3 text-sm">
                  <div>
                    <span className="font-medium">{s.document_type}</span>{" "}
                    <span className="text-muted-foreground">({s.file_type})</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {s.match_score != null && (
                      <span className="text-muted-foreground">{s.match_score}%</span>
                    )}
                    <Badge variant={statusVariant(s.status)}>{s.status}</Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
