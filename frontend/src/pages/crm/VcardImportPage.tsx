import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Upload, FileUp, Contact } from "lucide-react";

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
import { NotEnabledCard, isFeatureOff } from "./NotEnabledCard";
import { importVcard, type CctPartyOut } from "@/api/endpoints/partyCrm";

export default function VcardImportPage() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [imported, setImported] = useState<CctPartyOut[]>([]);
  const [featureOff, setFeatureOff] = useState(false);

  const importMut = useMutation({
    mutationFn: (file: File) => importVcard(file),
    onSuccess: (parties) => {
      setImported(parties);
      toast.success(`Imported ${parties.length} contact(s)`);
      setSelectedFile(null);
      if (fileRef.current) fileRef.current.value = "";
    },
    onError: (err: unknown) => {
      if (isFeatureOff(err)) {
        setFeatureOff(true);
        return;
      }
      toast.error(err instanceof Error ? err.message : "vCard import failed");
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="vCard Import"
        description="SuiteCRM party-CRM vCard 3.0 contact import (CCT-006)"
      />

      {featureOff ? (
        <NotEnabledCard
          feature="vCard Import"
          detail="The party_crm feature flag is off."
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FileUp className="h-5 w-5" />
              Upload a .vcf file
            </CardTitle>
            <CardDescription>
              Each VCARD record in the file becomes a party (up to 500 records).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <input
              ref={fileRef}
              type="file"
              accept=".vcf,text/vcard"
              aria-label="vCard file"
              className="block w-full text-sm text-muted-foreground file:mr-4 file:rounded-md file:border file:border-input file:bg-background file:px-3 file:py-2 file:text-sm"
              onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
            />
            <div className="flex items-center gap-2">
              <Button
                onClick={() => selectedFile && importMut.mutate(selectedFile)}
                disabled={!selectedFile || importMut.isPending}
              >
                <Upload className="mr-2 h-4 w-4" />
                {importMut.isPending ? "Importing…" : "Import"}
              </Button>
              {selectedFile && (
                <span className="text-sm text-muted-foreground">{selectedFile.name}</span>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {imported.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Contact className="h-5 w-5" />
              Imported parties
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Party id</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {imported.map((p) => (
                  <TableRow key={p.party_id}>
                    <TableCell className="font-mono text-xs">{p.party_id}</TableCell>
                    <TableCell>{p.display_name || p.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{p.party_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{p.status}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
