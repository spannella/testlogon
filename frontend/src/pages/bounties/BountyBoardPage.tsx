/**
 * BountyBoardPage — TBT-001..TBT-009
 *
 * Three views:
 *   "board"    — public board of open (funded) bounties
 *   "my"       — bounties I've claimed or submitted
 *   "post"     — fund a new bounty on an existing ticket I own
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Award, RefreshCw, ChevronRight, Tag, Clock } from "lucide-react";

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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import {
  listOpenBounties,
  getBountyTicket,
  postBounty,
  claimBounty,
  unclaimBounty,
  submitBounty,
  cancelBounty,
  formatCents,
  bountyStatusLabel,
  type BountyBoardItem,
  type BountyTicket,
} from "@/api/endpoints/bounties";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function bountyStatusColor(
  status: string | null | undefined,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "funded":
      return "default";
    case "claimed":
      return "secondary";
    case "submitted":
      return "outline";
    case "paid_out":
      return "secondary";
    case "cancelled":
      return "destructive";
    default:
      return "outline";
  }
}

// ─── Feature-disabled banner ─────────────────────────────────────────────────

function FeatureDisabledBanner() {
  return (
    <Card className="border-dashed">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-muted-foreground">
          <Award className="h-5 w-5" />
          Bounty Board Not Enabled
        </CardTitle>
        <CardDescription>
          The ticket bounty feature is currently disabled on this instance.
          Contact your administrator to enable it.
        </CardDescription>
      </CardHeader>
    </Card>
  );
}

// ─── Bounty Board Item Card ───────────────────────────────────────────────────

interface BountyCardProps {
  item: BountyBoardItem;
  currentUserSub: string | null;
  onClaim: (ticketId: string) => void;
  isClaiming: boolean;
}

function BountyCard({ item, currentUserSub, onClaim, isClaiming }: BountyCardProps) {
  const isOwner = currentUserSub === item.owner_sub;

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-base truncate">{item.subject}</CardTitle>
            <CardDescription className="text-xs mt-1">
              ID: {item.ticket_id}
            </CardDescription>
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0">
            <span className="text-lg font-bold text-green-600 dark:text-green-400">
              {formatCents(item.bounty_amount_cents, item.bounty_currency)}
            </span>
            <Badge variant={bountyStatusColor(item.bounty_status)}>
              {bountyStatusLabel(item.bounty_status)}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        {item.labels.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-3">
            {item.labels.map((label) => (
              <Badge key={label} variant="outline" className="text-xs">
                <Tag className="h-3 w-3 mr-1" />
                {label}
              </Badge>
            ))}
          </div>
        )}
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            Posted {fmt(item.bounty_funded_at || item.created_at)}
          </span>
          {!isOwner && item.bounty_status === "funded" && (
            <Button
              size="sm"
              onClick={() => onClaim(item.ticket_id)}
              disabled={isClaiming}
            >
              Claim Bounty
              <ChevronRight className="h-4 w-4 ml-1" />
            </Button>
          )}
          {isOwner && (
            <span className="text-muted-foreground italic">Your bounty</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── My Bounties Item ────────────────────────────────────────────────────────

interface MyBountyCardProps {
  ticket: BountyTicket;
  currentUserSub: string | null;
  onUnclaim: (ticketId: string) => void;
  onSubmit: (ticketId: string) => void;
  onCancel: (ticketId: string) => void;
  isPending: boolean;
}

function MyBountyCard({
  ticket,
  currentUserSub,
  onUnclaim,
  onSubmit,
  onCancel,
  isPending,
}: MyBountyCardProps) {
  const isClaimer = ticket.claimed_by_sub === currentUserSub;
  const isPoster = ticket.owner_sub === currentUserSub;
  const canUnclaim =
    isClaimer && ticket.bounty_status === "claimed";
  const canSubmit =
    isClaimer && ticket.bounty_status === "claimed";
  const canCancel =
    isPoster &&
    ticket.bounty_status === "funded";

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-base truncate">{ticket.subject}</CardTitle>
            <CardDescription className="text-xs mt-1">
              ID: {ticket.ticket_id}
            </CardDescription>
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0">
            <span className="text-lg font-bold text-green-600 dark:text-green-400">
              {formatCents(
                ticket.bounty_amount_cents ?? 0,
                ticket.bounty_currency ?? "usd",
              )}
            </span>
            <Badge variant={bountyStatusColor(ticket.bounty_status)}>
              {bountyStatusLabel(ticket.bounty_status)}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="text-xs text-muted-foreground mb-3 space-y-1">
          {ticket.claimed_at && (
            <div>Claimed: {fmt(ticket.claimed_at)}</div>
          )}
          {ticket.bounty_submitted_at && (
            <div>Submitted: {fmt(ticket.bounty_submitted_at)}</div>
          )}
          {ticket.bounty_paid_at && (
            <div>Paid out: {fmt(ticket.bounty_paid_at)}</div>
          )}
          {ticket.bounty_cancelled_at && (
            <div>Cancelled: {fmt(ticket.bounty_cancelled_at)}</div>
          )}
        </div>
        <div className="flex gap-2 flex-wrap">
          {canSubmit && (
            <Button
              size="sm"
              onClick={() => onSubmit(ticket.ticket_id)}
              disabled={isPending}
            >
              Submit Work
            </Button>
          )}
          {canUnclaim && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => onUnclaim(ticket.ticket_id)}
              disabled={isPending}
            >
              Unclaim
            </Button>
          )}
          {canCancel && (
            <Button
              size="sm"
              variant="destructive"
              onClick={() => onCancel(ticket.ticket_id)}
              disabled={isPending}
            >
              Cancel & Refund
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Post Bounty Form ─────────────────────────────────────────────────────────

function PostBountyForm() {
  const qc = useQueryClient();
  const [ticketId, setTicketId] = useState("");
  const [amountDollars, setAmountDollars] = useState("");
  const [ticketPreview, setTicketPreview] = useState<BountyTicket | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);

  const postMut = useMutation({
    mutationFn: ({ id, cents }: { id: string; cents: number }) =>
      postBounty(id, { amount_cents: cents, currency: "usd" }),
    onSuccess: (data) => {
      toast.success(
        `Bounty of ${formatCents(data.ticket.bounty_amount_cents ?? 0)} posted!`,
      );
      setTicketId("");
      setAmountDollars("");
      setTicketPreview(null);
      void qc.invalidateQueries({ queryKey: ["bounties", "open"] });
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "Failed to post bounty";
      toast.error(msg);
    },
  });

  async function loadPreview() {
    const id = ticketId.trim();
    if (!id) return;
    setIsLoadingPreview(true);
    setPreviewError(null);
    setTicketPreview(null);
    try {
      const res = await getBountyTicket(id);
      setTicketPreview(res.ticket);
    } catch (err: unknown) {
      const msg =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "Ticket not found";
      setPreviewError(msg);
    } finally {
      setIsLoadingPreview(false);
    }
  }

  function handlePost() {
    const id = ticketId.trim();
    const dollars = parseFloat(amountDollars);
    if (!id) {
      toast.error("Enter a ticket ID");
      return;
    }
    if (isNaN(dollars) || dollars < 0.01) {
      toast.error("Enter a valid amount (minimum $0.01)");
      return;
    }
    const cents = Math.round(dollars * 100);
    postMut.mutate({ id, cents });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Post a Bounty</CardTitle>
        <CardDescription>
          Fund a bounty on a ticket you own. The amount is deducted from your
          wallet and held in escrow until the work is approved.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="bounty-ticket-id">Ticket ID</Label>
          <div className="flex gap-2">
            <Input
              id="bounty-ticket-id"
              placeholder="e.g. tkt_abc123"
              value={ticketId}
              onChange={(e) => {
                setTicketId(e.target.value);
                setTicketPreview(null);
                setPreviewError(null);
              }}
            />
            <Button
              variant="outline"
              onClick={() => void loadPreview()}
              disabled={isLoadingPreview || !ticketId.trim()}
            >
              {isLoadingPreview ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                "Preview"
              )}
            </Button>
          </div>
          {previewError && (
            <p className="text-sm text-destructive">{previewError}</p>
          )}
        </div>

        {ticketPreview && (
          <Card className="bg-muted/50 border-dashed">
            <CardContent className="pt-4 pb-3">
              <p className="font-medium text-sm">{ticketPreview.subject}</p>
              <p className="text-xs text-muted-foreground mt-1">
                Status: {ticketPreview.status}
                {ticketPreview.bounty_status
                  ? ` · Bounty: ${bountyStatusLabel(ticketPreview.bounty_status)}`
                  : ""}
              </p>
            </CardContent>
          </Card>
        )}

        <div className="space-y-2">
          <Label htmlFor="bounty-amount">Amount (USD)</Label>
          <Input
            id="bounty-amount"
            type="number"
            min="0.01"
            step="0.01"
            placeholder="e.g. 50.00"
            value={amountDollars}
            onChange={(e) => setAmountDollars(e.target.value)}
          />
          {amountDollars && !isNaN(parseFloat(amountDollars)) && (
            <p className="text-xs text-muted-foreground">
              = {formatCents(Math.round(parseFloat(amountDollars) * 100))} will
              be deducted from your wallet
            </p>
          )}
        </div>

        <Button
          className="w-full"
          onClick={handlePost}
          disabled={
            postMut.isPending ||
            !ticketId.trim() ||
            !amountDollars
          }
        >
          {postMut.isPending ? (
            <>
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              Posting…
            </>
          ) : (
            <>
              <Award className="h-4 w-4 mr-2" />
              Post Bounty
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── My Bounties tab ─────────────────────────────────────────────────────────

interface MyBountiesTabProps {
  currentUserSub: string | null;
}

function MyBountiesTab({ currentUserSub }: MyBountiesTabProps) {
  const qc = useQueryClient();

  // Fetch claimed / submitted tickets for current user using list + filter
  // The bounty board only surfaces "funded"; for "my" view we re-use the
  // individual ticket lookup pattern. Since there's no "my claimed bounties"
  // list endpoint, we fetch the open board and the user's own claimed items
  // via the tickets list (which is scoped to the authenticated user).
  // We store ticket IDs from the board cache and augment with any the user
  // has claimed (fetched individually when they interact).
  // Practical approach: list user's own tickets filtered to bounty-active states.

  // Fetch tickets from /tickets with bounty_status in context
  // The tickets list returns full TicketOut which includes bounty fields.
  const myTicketsQuery = useQuery({
    queryKey: ["bounties", "my-tickets", currentUserSub],
    queryFn: async () => {
      // Fetch up to 50 user tickets — API returns newest first
      const res = await fetch("/tickets?limit=50", {
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { detail?: string } | null;
        throw new ApiError(res.status, body?.detail ?? res.statusText, body);
      }
      const data = (await res.json()) as {
        items: BountyTicket[];
      };
      return data.items.filter(
        (t) =>
          t.bounty_status !== null &&
          t.bounty_status !== undefined,
      );
    },
    enabled: !!currentUserSub,
    retry: false,
  });

  const unclaimMut = useMutation({
    mutationFn: (ticketId: string) => unclaimBounty(ticketId),
    onSuccess: () => {
      toast.success("Bounty unclaimed");
      void qc.invalidateQueries({ queryKey: ["bounties"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "Failed to unclaim",
      ),
  });

  const submitMut = useMutation({
    mutationFn: (ticketId: string) => submitBounty(ticketId),
    onSuccess: () => {
      toast.success("Work submitted for review!");
      void qc.invalidateQueries({ queryKey: ["bounties"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "Failed to submit",
      ),
  });

  const [cancelTargetId, setCancelTargetId] = useState<string | null>(null);
  const [cancelReason, setCancelReason] = useState("");

  const cancelMut = useMutation({
    mutationFn: ({ ticketId, reason }: { ticketId: string; reason: string }) =>
      cancelBounty(ticketId, { reason }),
    onSuccess: () => {
      toast.success("Bounty cancelled. Refund issued to wallet.");
      setCancelTargetId(null);
      setCancelReason("");
      void qc.invalidateQueries({ queryKey: ["bounties"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "Failed to cancel",
      ),
  });

  const isPending =
    unclaimMut.isPending || submitMut.isPending || cancelMut.isPending;

  if (myTicketsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <RefreshCw className="h-5 w-5 animate-spin mr-2" />
        Loading your bounties…
      </div>
    );
  }

  const tickets = myTicketsQuery.data ?? [];

  if (!tickets.length) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-muted-foreground text-base">
            No active bounties
          </CardTitle>
          <CardDescription>
            Claim a bounty from the board, or post one on a ticket you own.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <>
      <div className="grid gap-4 sm:grid-cols-2">
        {tickets.map((t) => (
          <MyBountyCard
            key={t.ticket_id}
            ticket={t}
            currentUserSub={currentUserSub}
            onUnclaim={(id) => unclaimMut.mutate(id)}
            onSubmit={(id) => submitMut.mutate(id)}
            onCancel={(id) => {
              setCancelTargetId(id);
              setCancelReason("");
            }}
            isPending={isPending}
          />
        ))}
      </div>

      {/* Cancel confirmation dialog */}
      <Dialog
        open={!!cancelTargetId}
        onOpenChange={(open) => {
          if (!open) setCancelTargetId(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel Bounty</DialogTitle>
            <DialogDescription>
              The bounty amount will be refunded to your wallet. This action
              cannot be undone once the bounty has been claimed.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="cancel-reason">Reason (optional)</Label>
            <Input
              id="cancel-reason"
              placeholder="Reason for cancellation"
              value={cancelReason}
              onChange={(e) => setCancelReason(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setCancelTargetId(null)}
            >
              Keep Bounty
            </Button>
            <Button
              variant="destructive"
              disabled={cancelMut.isPending}
              onClick={() => {
                if (cancelTargetId) {
                  cancelMut.mutate({
                    ticketId: cancelTargetId,
                    reason: cancelReason,
                  });
                }
              }}
            >
              {cancelMut.isPending ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Cancelling…
                </>
              ) : (
                "Cancel & Refund"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── Open Bounty Board tab ────────────────────────────────────────────────────

interface OpenBoardTabProps {
  currentUserSub: string | null;
}

function OpenBoardTab({ currentUserSub }: OpenBoardTabProps) {
  const qc = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const boardQuery = useQuery({
    queryKey: ["bounties", "open", cursor],
    queryFn: () => listOpenBounties({ limit: 25, cursor }),
    retry: false,
  });

  const claimMut = useMutation({
    mutationFn: (ticketId: string) => claimBounty(ticketId),
    onSuccess: (data) => {
      toast.success(`Claimed bounty for "${data.ticket.subject}"`);
      void qc.invalidateQueries({ queryKey: ["bounties"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "Failed to claim bounty",
      ),
  });

  if (boardQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <RefreshCw className="h-5 w-5 animate-spin mr-2" />
        Loading bounty board…
      </div>
    );
  }

  if (boardQuery.isError) {
    const err = boardQuery.error;
    if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
      return <FeatureDisabledBanner />;
    }
    return (
      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="text-destructive text-base">
            Failed to load bounty board
          </CardTitle>
          <CardDescription>
            {err instanceof Error ? err.message : "Unknown error"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void boardQuery.refetch()}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  const items = boardQuery.data?.items ?? [];
  const nextCursor = boardQuery.data?.next_cursor;

  if (!items.length) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-muted-foreground text-base">
            No open bounties
          </CardTitle>
          <CardDescription>
            There are no funded bounties available to claim right now. Check
            back later or post a bounty on a ticket you own.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        {items.map((item) => (
          <BountyCard
            key={item.ticket_id}
            item={item}
            currentUserSub={currentUserSub}
            onClaim={(id) => claimMut.mutate(id)}
            isClaiming={claimMut.isPending}
          />
        ))}
      </div>

      {/* Pagination */}
      <div className="flex justify-between items-center pt-2">
        <Button
          variant="outline"
          size="sm"
          disabled={!cursor}
          onClick={() => setCursor(undefined)}
        >
          First page
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!nextCursor || boardQuery.isFetching}
          onClick={() => {
            if (nextCursor) setCursor(nextCursor);
          }}
        >
          {boardQuery.isFetching ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            "Next page"
          )}
        </Button>
      </div>
    </div>
  );
}

// ─── Main page component ──────────────────────────────────────────────────────

export default function BountyBoardPage() {
  const currentUserSub = useAuthStore((s) => s.userId);

  return (
    <div className="space-y-6 p-6 max-w-4xl mx-auto">
      <PageHeader
        title="Bounty Board"
        description="Browse funded bounties, claim one to work on, or post a bounty on your own ticket."
        actions={
          <Badge variant="outline" className="text-sm px-3 py-1">
            <Award className="h-4 w-4 mr-1" />
            Bounties
          </Badge>
        }
      />

      <Tabs defaultValue="board">
        <TabsList className="mb-4">
          <TabsTrigger value="board">Open Bounties</TabsTrigger>
          <TabsTrigger value="my">My Bounties</TabsTrigger>
          <TabsTrigger value="post">Post a Bounty</TabsTrigger>
        </TabsList>

        <TabsContent value="board">
          <OpenBoardTab currentUserSub={currentUserSub} />
        </TabsContent>

        <TabsContent value="my">
          <MyBountiesTab currentUserSub={currentUserSub} />
        </TabsContent>

        <TabsContent value="post">
          <PostBountyForm />
        </TabsContent>
      </Tabs>
    </div>
  );
}
