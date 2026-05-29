import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Megaphone, Plus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { listMyAdAccounts, createAdAccount } from "@/api/endpoints/ads";
import type { AdAccount } from "@/api/types";

const statusVariant: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  pending_review: "secondary",
  active: "default",
  suspended: "destructive",
  rejected: "destructive",
};

export default function AdvertiserDashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [companyName, setCompanyName] = useState("");
  const [billingEmail, setBillingEmail] = useState("");

  const { data: accounts = [], isLoading } = useQuery({
    queryKey: ["ad-accounts"],
    queryFn: () => listMyAdAccounts(),
  });

  const createMut = useMutation({
    mutationFn: (data: { company_name: string; billing_email: string }) =>
      createAdAccount(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-accounts"] });
      setDialogOpen(false);
      setCompanyName("");
      setBillingEmail("");
    },
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Megaphone className="h-6 w-6" />
            <CardTitle>Advertiser Dashboard</CardTitle>
          </div>
          <Button onClick={() => setDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Advertiser Account
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground">Loading accounts...</p>
          ) : accounts.length === 0 ? (
            <p className="text-muted-foreground">
              No advertiser accounts yet. Create one to start running ads.
            </p>
          ) : (
            <div className="space-y-4">
              {(accounts as AdAccount[]).map((acct) => (
                <Card
                  key={acct.account_id}
                  className="cursor-pointer hover:bg-accent/50 transition-colors"
                  onClick={() =>
                    navigate(`/ads/campaigns?account=${acct.account_id}`)
                  }
                >
                  <CardContent className="flex items-center justify-between py-4">
                    <div>
                      <p className="font-semibold">{acct.company_name}</p>
                      <p className="text-sm text-muted-foreground">
                        {acct.billing_email}
                      </p>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right text-sm">
                        <p>Balance: ${(acct.balance_cents / 100).toFixed(2)}</p>
                        <p className="text-muted-foreground">
                          Lifetime: ${(acct.lifetime_spend_cents / 100).toFixed(2)}
                        </p>
                      </div>
                      <Badge variant={statusVariant[acct.status] ?? "outline"}>
                        {acct.status.replace("_", " ")}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Advertiser Account</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label htmlFor="company_name">Company Name</Label>
              <Input
                id="company_name"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="Acme Corp"
              />
            </div>
            <div>
              <Label htmlFor="billing_email">Billing Email</Label>
              <Input
                id="billing_email"
                type="email"
                value={billingEmail}
                onChange={(e) => setBillingEmail(e.target.value)}
                placeholder="billing@acme.com"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              onClick={() =>
                createMut.mutate({
                  company_name: companyName,
                  billing_email: billingEmail,
                })
              }
              disabled={!companyName || !billingEmail || createMut.isPending}
            >
              {createMut.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
