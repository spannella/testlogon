import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { DollarSign, TrendingUp, TrendingDown, Calculator } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import {
  getEarnedRevenue,
  getPaidRevenue,
  calculateSplitPreview,
} from "@/api/endpoints/license-revenue";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatDate(ts: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleDateString();
}

function sourceTypeBadge(type: string) {
  const colors: Record<string, string> = {
    tip: "bg-green-100 text-green-800",
    subscription: "bg-blue-100 text-blue-800",
    sale: "bg-purple-100 text-purple-800",
    unlock: "bg-orange-100 text-orange-800",
  };
  return (
    <Badge variant="outline" className={colors[type] || ""}>
      {type}
    </Badge>
  );
}

function splitTypeBadge(type: string) {
  if (type === "revenue_share") return <Badge variant="secondary">Rev Share</Badge>;
  if (type === "profit_share") return <Badge variant="secondary">Profit Share</Badge>;
  if (type === "fixed") return <Badge variant="secondary">Fixed Fee</Badge>;
  return <Badge variant="outline">{type}</Badge>;
}

export default function LicenseRevenuePage() {
  const [activeTab, setActiveTab] = useState("earned");
  const [sourceFilter, setSourceFilter] = useState<string>("all");

  const filterParam = sourceFilter === "all" ? undefined : sourceFilter;

  const earnedQuery = useQuery({
    queryKey: ["license-revenue", "earned", filterParam],
    queryFn: () => getEarnedRevenue({ source_type: filterParam }),
    enabled: activeTab === "earned",
  });

  const paidQuery = useQuery({
    queryKey: ["license-revenue", "paid", filterParam],
    queryFn: () => getPaidRevenue({ source_type: filterParam }),
    enabled: activeTab === "paid",
  });

  // Split calculator state
  const [calcAmount, setCalcAmount] = useState(1000);
  const [calcRevShare, setCalcRevShare] = useState(5);
  const [calcProfShare, setCalcProfShare] = useState(10);

  const calcQuery = useQuery({
    queryKey: ["license-revenue", "calc", calcAmount, calcRevShare, calcProfShare],
    queryFn: () =>
      calculateSplitPreview({
        amount: calcAmount,
        revenue_share_pct: calcRevShare,
        profit_share_pct: calcProfShare,
      }),
    enabled: activeTab === "calculator",
  });

  return (
    <div className="container mx-auto space-y-6 p-4">
      <div className="flex items-center gap-3">
        <DollarSign className="h-7 w-7" />
        <h1 className="text-2xl font-bold">License Revenue</h1>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="earned">
            <TrendingUp className="mr-1 h-4 w-4" /> Earned
          </TabsTrigger>
          <TabsTrigger value="paid">
            <TrendingDown className="mr-1 h-4 w-4" /> Paid
          </TabsTrigger>
          <TabsTrigger value="calculator">
            <Calculator className="mr-1 h-4 w-4" /> Calculator
          </TabsTrigger>
        </TabsList>

        {/* Source type filter */}
        {activeTab !== "calculator" && (
          <div className="mt-4 flex items-center gap-2">
            <Label>Source:</Label>
            <Select value={sourceFilter} onValueChange={setSourceFilter}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="tip">Tips</SelectItem>
                <SelectItem value="subscription">Subscriptions</SelectItem>
                <SelectItem value="sale">Sales</SelectItem>
                <SelectItem value="unlock">Unlocks</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}

        {/* Earned Tab */}
        <TabsContent value="earned">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-green-600" />
                Revenue Earned (Licensor)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {earnedQuery.data && (
                <div className="mb-6 grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Earned</p>
                    <p className="text-2xl font-bold text-green-600">
                      {formatCents(earnedQuery.data.summary.total_cents)}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Transactions</p>
                    <p className="text-2xl font-bold">
                      {earnedQuery.data.summary.total_transactions}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Last Transaction</p>
                    <p className="text-lg">
                      {formatDate(earnedQuery.data.summary.last_transaction_at ?? 0)}
                    </p>
                  </div>
                </div>
              )}
              <TransactionTable
                transactions={earnedQuery.data?.transactions ?? []}
                loading={earnedQuery.isLoading}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Paid Tab */}
        <TabsContent value="paid">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingDown className="h-5 w-5 text-red-600" />
                Revenue Paid (Licensee)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {paidQuery.data && (
                <div className="mb-6 grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Paid</p>
                    <p className="text-2xl font-bold text-red-600">
                      {formatCents(paidQuery.data.summary.total_cents)}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Transactions</p>
                    <p className="text-2xl font-bold">
                      {paidQuery.data.summary.total_transactions}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Last Transaction</p>
                    <p className="text-lg">
                      {formatDate(paidQuery.data.summary.last_transaction_at ?? 0)}
                    </p>
                  </div>
                </div>
              )}
              <TransactionTable
                transactions={paidQuery.data?.transactions ?? []}
                loading={paidQuery.isLoading}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Calculator Tab */}
        <TabsContent value="calculator">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Calculator className="h-5 w-5" />
                Split Calculator
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                <div>
                  <Label>Source Amount (cents)</Label>
                  <Input
                    type="number"
                    value={calcAmount}
                    onChange={(e) => setCalcAmount(Number(e.target.value))}
                    min={0}
                  />
                </div>
                <div>
                  <Label>Revenue Share %</Label>
                  <Input
                    type="number"
                    value={calcRevShare}
                    onChange={(e) => setCalcRevShare(Number(e.target.value))}
                    min={0}
                    max={100}
                  />
                </div>
                <div>
                  <Label>Profit Share %</Label>
                  <Input
                    type="number"
                    value={calcProfShare}
                    onChange={(e) => setCalcProfShare(Number(e.target.value))}
                    min={0}
                    max={100}
                  />
                </div>
              </div>

              {calcQuery.data && (
                <div className="mt-6 rounded-lg border p-4">
                  <h3 className="mb-3 font-semibold">Calculation Result</h3>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <span className="text-muted-foreground">Source Amount:</span>
                    <span>{formatCents(calcQuery.data.source_amount_cents)}</span>
                    <span className="text-muted-foreground">Platform Fee:</span>
                    <span>{formatCents(calcQuery.data.platform_fee_cents)}</span>
                    <span className="text-muted-foreground">Revenue Share:</span>
                    <span>{formatCents(calcQuery.data.revenue_share_cents)}</span>
                    <span className="text-muted-foreground">Profit Share:</span>
                    <span>{formatCents(calcQuery.data.profit_share_cents)}</span>
                    <span className="font-semibold">Licensor Total:</span>
                    <span className="font-semibold text-green-600">
                      {formatCents(calcQuery.data.total_licensor_share_cents)}
                    </span>
                    <span className="font-semibold">Licensee Net:</span>
                    <span className="font-semibold">
                      {formatCents(calcQuery.data.licensee_net_cents)}
                    </span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function TransactionTable({
  transactions,
  loading,
}: {
  transactions: Array<{
    txn_id: string;
    content_id: string;
    counterparty_id: string;
    source_type: string;
    source_amount_cents: number;
    split_amount_cents: number;
    split_type: string;
    created_at: number;
  }>;
  loading: boolean;
}) {
  if (loading) {
    return <p className="py-4 text-center text-muted-foreground">Loading...</p>;
  }
  if (!transactions.length) {
    return <p className="py-4 text-center text-muted-foreground">No transactions yet.</p>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Date</TableHead>
          <TableHead>Source</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Content</TableHead>
          <TableHead>Counterparty</TableHead>
          <TableHead className="text-right">Source Amt</TableHead>
          <TableHead className="text-right">Split Amt</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {transactions.map((txn) => (
          <TableRow key={txn.txn_id}>
            <TableCell>{formatDate(txn.created_at)}</TableCell>
            <TableCell>{sourceTypeBadge(txn.source_type)}</TableCell>
            <TableCell>{splitTypeBadge(txn.split_type)}</TableCell>
            <TableCell className="max-w-[120px] truncate">{txn.content_id}</TableCell>
            <TableCell className="max-w-[120px] truncate">{txn.counterparty_id}</TableCell>
            <TableCell className="text-right">{formatCents(txn.source_amount_cents)}</TableCell>
            <TableCell className="text-right font-medium">
              {formatCents(txn.split_amount_cents)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
