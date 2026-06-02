import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Languages, Save, Trash2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
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
import {
  adminDeleteKycTranslation,
  adminListKycTranslations,
  adminSetKycTranslation,
  getKycSupportedLocales,
} from "@/api/endpoints/kycTranslations";
import type { KycTranslation } from "@/api/types";

const STATUS_COLORS: Record<string, string> = {
  published: "bg-green-100 text-green-800",
  draft: "bg-yellow-100 text-yellow-800",
  needs_review: "bg-orange-100 text-orange-800",
};

export default function KycTranslationsPage() {
  const qc = useQueryClient();
  const [language, setLanguage] = useState("es");
  const [prefix, setPrefix] = useState("");
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const [edits, setEdits] = useState<Record<string, string>>({});

  const localesQuery = useQuery({
    queryKey: ["kyc-i18n", "locales"],
    queryFn: getKycSupportedLocales,
  });

  const listQuery = useQuery({
    queryKey: ["kyc-i18n", "admin", language, prefix],
    queryFn: () =>
      adminListKycTranslations(language, prefix ? { prefix } : undefined),
  });

  const coverage = listQuery.data?.coverage;
  const coveragePct = useMemo(
    () => Math.round((coverage?.coverage_pct ?? 0) * 100),
    [coverage],
  );

  const setMut = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) =>
      adminSetKycTranslation(language, key, { value }),
    onSuccess: () => {
      toast.success("Translation saved");
      qc.invalidateQueries({ queryKey: ["kyc-i18n", "admin", language] });
    },
    onError: () => toast.error("Failed to save translation"),
  });

  const delMut = useMutation({
    mutationFn: (key: string) => adminDeleteKycTranslation(language, key),
    onSuccess: () => {
      toast.success("Translation deleted");
      qc.invalidateQueries({ queryKey: ["kyc-i18n", "admin", language] });
    },
    onError: () => toast.error("Failed to delete translation"),
  });

  const items = listQuery.data?.items ?? [];

  function handleCreate() {
    if (!newKey.trim() || !newValue.trim()) {
      toast.error("Key and value are required");
      return;
    }
    setMut.mutate({ key: newKey.trim(), value: newValue.trim() });
    setNewKey("");
    setNewValue("");
  }

  return (
    <div className="space-y-6 p-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Languages className="h-5 w-5" />
            KYC Translations
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">Language</label>
              <Select value={language} onValueChange={setLanguage}>
                <SelectTrigger className="w-48" data-testid="kyc-lang-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(localesQuery.data?.locales ?? []).map((l) => (
                    <SelectItem key={l.code} value={l.code}>
                      {l.name} ({l.code})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Key prefix filter</label>
              <Input
                className="w-64"
                placeholder="kyc.status"
                value={prefix}
                onChange={(e) => setPrefix(e.target.value)}
                data-testid="kyc-prefix-filter"
              />
            </div>
          </div>

          <div className="space-y-1" data-testid="kyc-coverage-bar">
            <div className="flex justify-between text-sm">
              <span>Coverage ({language})</span>
              <span>
                {coverage?.translated_keys ?? 0} / {coverage?.total_keys ?? 0} ({coveragePct}%)
              </span>
            </div>
            <Progress value={coveragePct} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Add / update translation</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <Input
            className="w-80 font-mono text-xs"
            placeholder="kyc.status.approved"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            data-testid="kyc-new-key"
          />
          <Input
            className="flex-1"
            placeholder="Translated value"
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
            data-testid="kyc-new-value"
          />
          <Button onClick={handleCreate} disabled={setMut.isPending} data-testid="kyc-add-btn">
            <Save className="mr-1 h-4 w-4" />
            Save
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Key</TableHead>
                <TableHead>Translation</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">
                    {listQuery.isLoading ? "Loading…" : "No translations"}
                  </TableCell>
                </TableRow>
              )}
              {items.map((item: KycTranslation) => {
                const edited = edits[item.key];
                const value = edited ?? item.value;
                return (
                  <TableRow key={item.key} data-testid={`kyc-row-${item.key}`}>
                    <TableCell className="font-mono text-xs">{item.key}</TableCell>
                    <TableCell>
                      <Input
                        value={value}
                        onChange={(e) =>
                          setEdits((prev) => ({ ...prev, [item.key]: e.target.value }))
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Badge className={STATUS_COLORS[item.status ?? "published"]}>
                        {item.status ?? "published"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setMut.mutate({ key: item.key, value })}
                        >
                          <Save className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => delMut.mutate(item.key)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
