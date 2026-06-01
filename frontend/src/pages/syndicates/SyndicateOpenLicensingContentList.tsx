import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  listOpenLicensingContent,
  exemptOpenLicensingContent,
  removeOpenLicensingExemption,
} from "@/api/endpoints/syndicateOpenLicensing";

export default function SyndicateOpenLicensingContentList({
  syndicateId,
  currentUserId,
}: {
  syndicateId: string;
  currentUserId: string;
}) {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["open-licensing-content", syndicateId],
    queryFn: () => listOpenLicensingContent(syndicateId).then((r) => r.items),
  });

  const exemptMut = useMutation({
    mutationFn: (contentId: string) =>
      exemptOpenLicensingContent(syndicateId, contentId),
    onSuccess: () => {
      toast.success("Content exempted");
      qc.invalidateQueries({ queryKey: ["open-licensing-content", syndicateId] });
    },
    onError: () => toast.error("Failed to exempt content"),
  });

  const unexemptMut = useMutation({
    mutationFn: (contentId: string) =>
      removeOpenLicensingExemption(syndicateId, contentId),
    onSuccess: () => {
      toast.success("Exemption removed");
      qc.invalidateQueries({ queryKey: ["open-licensing-content", syndicateId] });
    },
    onError: () => toast.error("Failed to remove exemption"),
  });

  const items = data ?? [];
  if (items.length === 0) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="ol-no-content">
        No content registered under open licensing yet.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Content</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Creator</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((c) => {
          const isOwner = c.creator_id === currentUserId;
          return (
            <TableRow key={c.content_id} data-testid={`ol-row-${c.content_id}`}>
              <TableCell className="font-mono text-xs">{c.content_id}</TableCell>
              <TableCell>
                <Badge variant="secondary">{c.content_type}</Badge>
              </TableCell>
              <TableCell className="text-xs">{c.creator_id}</TableCell>
              <TableCell>
                {c.exempt ? (
                  <Badge variant="outline">Exempt</Badge>
                ) : (
                  <Badge>Auto-licensed</Badge>
                )}
              </TableCell>
              <TableCell className="text-right">
                {isOwner &&
                  (c.exempt ? (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => unexemptMut.mutate(c.content_id)}
                    >
                      Remove Exemption
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => exemptMut.mutate(c.content_id)}
                    >
                      Exempt
                    </Button>
                  ))}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
