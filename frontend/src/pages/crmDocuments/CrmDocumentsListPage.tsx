import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { FileBox, Search, Upload } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Skeleton } from "@/components/ui/skeleton";

import {
  searchCrmDocuments,
  type LinkedRecordType,
} from "@/api/endpoints/crmDocuments";
import {
  CrmDocumentsNotEnabled,
  EmptyDocs,
  RECORD_TYPE_OPTIONS,
  encodeDocPath,
  fmtTs,
  isNotEnabled,
} from "./crmDocumentsShared";
import { ApiError } from "@/api/client";

export default function CrmDocumentsListPage() {
  const [recordType, setRecordType] = useState<LinkedRecordType>("contact");
  const [recordId, setRecordId] = useState("");
  const [submitted, setSubmitted] = useState<{ type: LinkedRecordType; id: string } | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [cursorStack, setCursorStack] = useState<string[]>([]);

  const searchQuery = useQuery({
    queryKey: ["crm-documents", "search", submitted?.type, submitted?.id, cursor],
    queryFn: () =>
      searchCrmDocuments({
        linked_record_type: submitted!.type,
        linked_record_id: submitted!.id,
        limit: 25,
        cursor,
      }),
    enabled: !!submitted && submitted.id.trim().length > 0,
    retry: false,
  });

  const notEnabled = isNotEnabled(searchQuery.error);
  const status = (searchQuery.error as ApiError | undefined)?.status;

  function doSearch() {
    const id = recordId.trim();
    if (!id) return;
    setCursor(undefined);
    setCursorStack([]);
    setSubmitted({ type: recordType, id });
  }

  function nextPage(next: string) {
    setCursorStack((s) => [...s, cursor ?? ""]);
    setCursor(next);
  }
  function prevPage() {
    setCursorStack((s) => {
      const copy = [...s];
      const prev = copy.pop();
      setCursor(prev || undefined);
      return copy;
    });
  }

  const items = searchQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="CRM Documents"
        description="Find documents linked to a CRM record (contact, account, ticket, or party)."
        actions={
          <Button asChild>
            <Link to="/crm/documents/upload">
              <Upload className="mr-2 h-4 w-4" />
              Upload &amp; link
            </Link>
          </Button>
        }
      />

      {notEnabled || status === 403 || status === 401 ? (
        <CrmDocumentsNotEnabled status={status} />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Search className="h-4 w-4" />
                Find by linked record
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <div className="space-y-1">
                  <Label htmlFor="record-type">Record type</Label>
                  <Select
                    value={recordType}
                    onValueChange={(v) => setRecordType(v as LinkedRecordType)}
                  >
                    <SelectTrigger id="record-type" className="w-[180px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {RECORD_TYPE_OPTIONS.map((t) => (
                        <SelectItem key={t} value={t}>
                          {t.charAt(0).toUpperCase() + t.slice(1)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1 space-y-1">
                  <Label htmlFor="record-id">Record ID</Label>
                  <Input
                    id="record-id"
                    placeholder="e.g. contact_abc123"
                    value={recordId}
                    onChange={(e) => setRecordId(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") doSearch();
                    }}
                  />
                </div>
                <Button onClick={doSearch} disabled={!recordId.trim()}>
                  <Search className="mr-2 h-4 w-4" />
                  Search
                </Button>
              </div>
            </CardContent>
          </Card>

          {!submitted ? (
            <EmptyDocs message="Enter a record type and ID above to find linked documents." />
          ) : searchQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : searchQuery.isError ? (
            <EmptyDocs message="Could not load documents. Try again." />
          ) : items.length === 0 ? (
            <EmptyDocs
              message={`No documents linked to ${submitted.type} "${submitted.id}".`}
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <FileBox className="h-4 w-4" />
                  {searchQuery.data?.count ?? items.length} document
                  {items.length === 1 ? "" : "s"}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Document</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Updated</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((d) => {
                      const name = d.path.split("/").filter(Boolean).pop() || d.path;
                      return (
                        <TableRow key={d.path}>
                          <TableCell>
                            <div className="font-medium">{name}</div>
                            <div className="text-xs text-muted-foreground">{d.path}</div>
                            {d.crm_description && (
                              <div className="mt-1 line-clamp-1 text-xs text-muted-foreground">
                                {d.crm_description}
                              </div>
                            )}
                          </TableCell>
                          <TableCell>
                            {d.crm_category ? (
                              <Badge variant="secondary">{d.crm_category}</Badge>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {fmtTs(d.crm_metadata_updated_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button asChild variant="ghost" size="sm">
                              <Link to={`/crm/documents/detail/${encodeDocPath(d.path)}`}>
                                View
                              </Link>
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {submitted && (searchQuery.data?.cursor || cursorStack.length > 0) && (
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={prevPage}
                disabled={cursorStack.length === 0}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => searchQuery.data?.cursor && nextPage(searchQuery.data.cursor)}
                disabled={!searchQuery.data?.cursor}
              >
                Next
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
