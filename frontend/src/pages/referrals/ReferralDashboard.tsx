import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Share2, Copy, X, Plus, Users, DollarSign, Clock, CheckCircle } from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import {
  createReferralCode,
  deactivateReferralCode,
  getReferralDashboard,
  getReferralCommissions,
} from "@/api/endpoints/referrals";
import type { ReferralDashboardStats, AffiliateCommission } from "@/api/types";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function ReferralDashboard() {
  const qc = useQueryClient();
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  const dashboardQuery = useQuery({
    queryKey: ["referrals", "dashboard"],
    queryFn: () => getReferralDashboard(),
  });

  const commissionsQuery = useQuery({
    queryKey: ["referrals", "commissions"],
    queryFn: () => getReferralCommissions({ limit: 50 }),
  });

  const createMut = useMutation({
    mutationFn: () => createReferralCode(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["referrals"] });
      setShowCreateDialog(false);
      toast.success("Referral code created");
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || "Failed to create code";
      toast.error(msg);
    },
  });

  const deactivateMut = useMutation({
    mutationFn: (code: string) => deactivateReferralCode(code),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["referrals"] });
      toast.success("Code deactivated");
    },
  });

  const stats: ReferralDashboardStats | undefined = dashboardQuery.data;
  const commissions: AffiliateCommission[] = commissionsQuery.data?.commissions ?? [];

  const copyLink = (code: string) => {
    const link = `${window.location.origin}/?ref=${code}`;
    navigator.clipboard.writeText(link).then(
      () => toast.success("Link copied to clipboard"),
      () => toast.error("Failed to copy"),
    );
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Share2 className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Referrals</h1>
          <p className="text-sm text-muted-foreground">
            Share your referral link and earn commission on referred purchases.
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Referrals</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-total-referrals">
              {stats?.total_referrals ?? 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats?.confirmed_referrals ?? 0} confirmed, {stats?.pending_referrals ?? 0} pending
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Earned</CardTitle>
            <DollarSign className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-total-earned">
              {formatCents(stats?.total_earned_cents ?? 0)}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-pending">
              {formatCents(stats?.pending_commission_cents ?? 0)}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Available</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-available">
              {formatCents(stats?.available_for_withdrawal_cents ?? 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Referral Codes Section */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Referral Codes</CardTitle>
            <CardDescription>
              Share these codes with others. You can have up to 5 active codes.
            </CardDescription>
          </div>
          <Button size="sm" onClick={() => setShowCreateDialog(true)}>
            <Plus className="mr-2 h-4 w-4" /> New Code
          </Button>
        </CardHeader>
        <CardContent>
          {stats?.referral_codes && stats.referral_codes.length > 0 ? (
            <div className="space-y-3">
              {stats.referral_codes.map((rc) => (
                <div
                  key={rc.code}
                  className="flex items-center justify-between rounded-lg border p-3"
                >
                  <div className="flex items-center gap-3">
                    <code className="rounded bg-muted px-2 py-1 font-mono text-sm">
                      {rc.code}
                    </code>
                    <Badge variant={rc.active ? "default" : "secondary"}>
                      {rc.active ? "Active" : "Inactive"}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {rc.referral_count ?? 0} referrals
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {rc.active && (
                      <>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyLink(rc.code)}
                          aria-label={`Copy link for ${rc.code}`}
                        >
                          <Copy className="mr-1 h-3 w-3" /> Copy Link
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deactivateMut.mutate(rc.code)}
                          aria-label={`Deactivate ${rc.code}`}
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              No referral codes yet. Click "New Code" to generate one.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Commission History */}
      <Card>
        <CardHeader>
          <CardTitle>Commission History</CardTitle>
          <CardDescription>Earnings from referred user purchases.</CardDescription>
        </CardHeader>
        <CardContent>
          {commissions.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Commission</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {commissions.map((c, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-xs">
                      {c.created_at}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{c.source_type}</Badge>
                    </TableCell>
                    <TableCell>{formatCents(c.gross_amount_cents)}</TableCell>
                    <TableCell className="font-medium">
                      {formatCents(c.commission_cents)}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          c.status === "confirmed"
                            ? "default"
                            : c.status === "paid"
                              ? "default"
                              : "secondary"
                        }
                      >
                        {c.status}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">No commissions yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Create Code Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate Referral Code</DialogTitle>
            <DialogDescription>
              A new 8-character code will be generated. Share the link with friends
              to earn 5% commission on their purchases.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending}
            >
              {createMut.isPending ? "Creating..." : "Generate Code"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
