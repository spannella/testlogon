import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listStaleDocs, updateDocRecord } from "@/api/endpoints/docsAgent";
import { Button } from "@/components/ui/button";

export default function StaleDocsPanel() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["doc-stale"],
    queryFn: () => listStaleDocs(100).catch(() => ({ docs: [], count: 0 })),
  });
  const refreshMut = useMutation({
    mutationFn: (docPath: string) => updateDocRecord(docPath, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["doc-stale"] });
      queryClient.invalidateQueries({ queryKey: ["doc-coverage"] });
      queryClient.invalidateQueries({ queryKey: ["doc-details"] });
    },
  });
  const docs = data?.docs ?? [];
  return (
    <div data-testid="stale-docs-panel" className="space-y-3">
      <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
        These docs need attention — they reference source files that have changed.
      </div>
      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading…</div>
      ) : docs.length === 0 ? (
        <div className="text-sm text-muted-foreground">No stale docs</div>
      ) : (
        <ul className="space-y-2">
          {docs.map((doc) => (
            <li
              key={doc.doc_path}
              className="flex items-center justify-between gap-3 rounded-md border p-3"
            >
              <div className="min-w-0">
                <span className="font-mono text-sm">{doc.doc_path}</span>
                <div className="text-xs text-red-500">
                  changed source: {doc.source_refs.join(", ") || "—"}
                </div>
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={() => refreshMut.mutate(doc.doc_path)}
                disabled={refreshMut.isPending}
              >
                Refresh Now
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
