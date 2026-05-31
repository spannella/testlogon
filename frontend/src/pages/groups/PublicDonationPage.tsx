import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  getPublicFundraiser,
  submitDonation,
  getDonationReceipt,
} from "@/api/endpoints/groups";
import type { GroupDonationReceipt } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Heart, CheckCircle2 } from "lucide-react";

function fmt(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

const PRESETS = [500, 1000, 2500, 5000];

export default function PublicDonationPage() {
  const { fundraiserId } = useParams<{ fundraiserId: string }>();

  const [amount, setAmount] = useState("");
  const [donorName, setDonorName] = useState("");
  const [donorEmail, setDonorEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<GroupDonationReceipt | null>(null);

  const fundraiserQ = useQuery({
    queryKey: ["public-fundraiser", fundraiserId],
    queryFn: () => getPublicFundraiser(fundraiserId!),
    enabled: !!fundraiserId,
    staleTime: 60_000,
  });

  if (!fundraiserId) return <div>Missing fundraiser ID</div>;

  const fundraiser = fundraiserQ.data;

  const handleDonate = async () => {
    const cents = Math.round(parseFloat(amount) * 100);
    if (!cents || cents < 100) {
      setError("Minimum donation is $1.00");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const donation = await submitDonation(fundraiserId, {
        amount_cents: cents,
        donor_name: donorName || undefined,
        donor_email: donorEmail || undefined,
      });
      try {
        const r = await getDonationReceipt(fundraiserId, donation.donation_id);
        setReceipt(r);
      } catch {
        // receipt not ready yet — show a minimal confirmation
        setReceipt({
          donation_id: donation.donation_id,
          amount_cents: donation.amount_cents,
          currency: "usd",
          donor_name: donorName || null,
          group_name: fundraiser?.group_name || "",
          fundraiser_title: fundraiser?.title || "",
          created_at: Math.floor(Date.now() / 1000),
          status: donation.status,
        });
      }
      fundraiserQ.refetch();
    } catch (e) {
      setError((e as Error)?.message || "Donation failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-lg space-y-6 p-6" data-testid="public-donation-page">
      {fundraiserQ.isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      ) : !fundraiser ? (
        <p className="text-center text-muted-foreground">Fundraiser not found.</p>
      ) : (
        <>
          <Card>
            <CardHeader>
              <div className="text-sm text-muted-foreground" data-testid="donation-group-name">
                {fundraiser.group_name}
              </div>
              <CardTitle className="flex items-center gap-2" data-testid="donation-title">
                <Heart className="h-5 w-5 text-rose-500" />
                {fundraiser.title}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {fundraiser.description && (
                <p className="text-sm text-muted-foreground">{fundraiser.description}</p>
              )}
              {fundraiser.goal_cents && fundraiser.goal_cents > 0 ? (
                <div data-testid="donation-progress">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium">{fmt(fundraiser.raised_cents)}</span>
                    <span className="text-muted-foreground">of {fmt(fundraiser.goal_cents)}</span>
                  </div>
                  <div className="mt-1 h-2 rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{
                        width: `${Math.min(100, Math.round((fundraiser.raised_cents / fundraiser.goal_cents) * 100))}%`,
                      }}
                    />
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {Math.round((fundraiser.raised_cents / fundraiser.goal_cents) * 100)}% of goal ·{" "}
                    {fundraiser.donation_count} donation
                    {fundraiser.donation_count !== 1 ? "s" : ""}
                  </div>
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">
                  {fmt(fundraiser.raised_cents)} raised
                </div>
              )}
            </CardContent>
          </Card>

          {receipt ? (
            <Card data-testid="donation-receipt">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  Thank you!
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 text-sm">
                <div>
                  Donation: <span className="font-semibold">{fmt(receipt.amount_cents)}</span>
                </div>
                <div>To: {receipt.group_name}</div>
                <div>For: {receipt.fundraiser_title}</div>
                <div className="text-xs text-muted-foreground">
                  Receipt {receipt.donation_id} · {receipt.status}
                </div>
              </CardContent>
            </Card>
          ) : fundraiser.status !== "active" ? (
            <p className="text-center text-muted-foreground" data-testid="donation-closed">
              This fundraiser is not currently accepting donations.
            </p>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Make a Donation</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-wrap gap-2" data-testid="amount-presets">
                  {PRESETS.map((cents) => (
                    <Button
                      key={cents}
                      variant="outline"
                      size="sm"
                      onClick={() => setAmount((cents / 100).toString())}
                    >
                      {fmt(cents)}
                    </Button>
                  ))}
                </div>
                <div>
                  <Label htmlFor="donate-amount">Amount ($)</Label>
                  <Input
                    id="donate-amount"
                    type="number"
                    min="1"
                    step="0.01"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    placeholder="0.00"
                    data-testid="donation-amount-input"
                  />
                </div>
                <div>
                  <Label htmlFor="donate-name">Your Name (optional)</Label>
                  <Input
                    id="donate-name"
                    value={donorName}
                    onChange={(e) => setDonorName(e.target.value)}
                    placeholder="Jane Smith"
                    data-testid="donor-name-input"
                  />
                </div>
                <div>
                  <Label htmlFor="donate-email">Email (optional)</Label>
                  <Input
                    id="donate-email"
                    type="email"
                    value={donorEmail}
                    onChange={(e) => setDonorEmail(e.target.value)}
                    placeholder="jane@example.com"
                    data-testid="donor-email-input"
                  />
                </div>
                {error && <p className="text-sm text-destructive">{error}</p>}
                <Button
                  onClick={handleDonate}
                  disabled={submitting || !amount || parseFloat(amount) < 1}
                  className="w-full"
                  data-testid="submit-donation-button"
                >
                  {submitting ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    `Donate ${amount ? fmt(Math.round(parseFloat(amount) * 100)) : ""}`
                  )}
                </Button>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
