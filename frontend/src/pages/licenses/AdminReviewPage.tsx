import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  adminListLicenseReviewQueue,
  adminReviewLicenseAgreement,
} from "@/api/endpoints/licenseAgreements";
import type { LicenseAgreementReviewItemOut } from "@/api/types";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function AdminReviewPage() {
  const queryClient = useQueryClient();
  const [reasons, setReasons] = useState<Record<string, string>>({});

  const queueQuery = useQuery({
    queryKey: ["license-review-queue"],
    queryFn: () => adminListLicenseReviewQueue({ limit: 50 }),
  });

  const reviewMut = useMutation({
    mutationFn: async (args: {
      id: string;
      verified: boolean;
      reason?: string;
    }) =>
      adminReviewLicenseAgreement(args.id, {
        verified: args.verified,
        rejection_reason: args.reason,
      }),
    onSuccess: () => {
      toast.success("Review recorded");
      queryClient.invalidateQueries({ queryKey: ["license-review-queue"] });
    },
    onError: (e: Error) => toast.error(e.message || "Review failed"),
  });

  const items: LicenseAgreementReviewItemOut[] = queueQuery.data?.items ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        title="License Agreement Review"
        description="Verify or reject creator-uploaded license agreements."
      />
      <Card>
        <CardHeader>
          <CardTitle>Pending Review</CardTitle>
          <CardDescription>
            {items.length} agreement{items.length === 1 ? "" : "s"} awaiting
            review
          </CardDescription>
        </CardHeader>
        <CardContent>
          {items.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No agreements pending review.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Creator</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Licensor</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((it) => (
                  <TableRow key={it.license_id}>
                    <TableCell>
                      {it.creator_display_name || it.creator_id}
                    </TableCell>
                    <TableCell className="font-medium">{it.title}</TableCell>
                    <TableCell>{it.licensor_name}</TableCell>
                    <TableCell>{it.license_type.replace(/_/g, " ")}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Input
                          className="w-40"
                          placeholder="Rejection reason"
                          value={reasons[it.license_id] ?? ""}
                          onChange={(e) =>
                            setReasons((r) => ({
                              ...r,
                              [it.license_id]: e.target.value,
                            }))
                          }
                        />
                        <Button
                          size="sm"
                          onClick={() =>
                            reviewMut.mutate({
                              id: it.license_id,
                              verified: true,
                            })
                          }
                          disabled={reviewMut.isPending}
                        >
                          Verify
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() =>
                            reviewMut.mutate({
                              id: it.license_id,
                              verified: false,
                              reason: reasons[it.license_id] ?? "",
                            })
                          }
                          disabled={reviewMut.isPending}
                        >
                          Reject
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
