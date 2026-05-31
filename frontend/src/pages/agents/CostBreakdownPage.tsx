import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  getDailyCostSummary,
  listTicketCosts,
} from "@/api/endpoints/accountantAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatCents } from "./OptimizationsPanel";

function todayStr(): string {
  return new Date().toISOString().slice(0, 10);
}

export default function CostBreakdownPage() {
  const [date, setDate] = useState(todayStr());

  const { data: daily } = useQuery({
    queryKey: ["accountant", "daily", date],
    queryFn: () => getDailyCostSummary(date),
    staleTime: 15_000,
  });
  const { data: ticketData } = useQuery({
    queryKey: ["accountant", "ticket-costs"],
    queryFn: () => listTicketCosts(50),
    staleTime: 15_000,
  });

  const byType = Object.entries(daily?.by_agent_type ?? {}).sort((a, b) => b[1] - a[1]);
  const workers = daily?.by_worker ?? [];
  const tickets = ticketData?.ticket_costs ?? [];

  return (
    <div className="space-y-4 p-4" data-testid="cost-breakdown-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Cost Breakdown</h1>
        <div className="flex items-center gap-2">
          <label className="text-sm text-muted-foreground">Date</label>
          <Input
            type="date"
            value={date}
            onChange={(e) => setDate(e.target.value)}
            data-testid="breakdown-date"
            className="w-40"
          />
        </div>
      </div>

      <Tabs defaultValue="agent-type">
        <TabsList>
          <TabsTrigger value="agent-type">By Agent Type</TabsTrigger>
          <TabsTrigger value="worker">By Worker</TabsTrigger>
          <TabsTrigger value="ticket">By Ticket</TabsTrigger>
        </TabsList>

        <TabsContent value="agent-type">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">By Agent Type</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="breakdown-table-agent-type">
                <TableHeader>
                  <TableRow>
                    <TableHead>Agent Type</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {byType.map(([type, cents]) => (
                    <TableRow key={type}>
                      <TableCell>{type}</TableCell>
                      <TableCell className="text-right">{formatCents(cents)}</TableCell>
                    </TableRow>
                  ))}
                  {byType.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={2} className="text-muted-foreground">
                        No spend for this date.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="worker">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">By Worker</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="breakdown-table-worker">
                <TableHeader>
                  <TableRow>
                    <TableHead>Worker</TableHead>
                    <TableHead>Agent Type</TableHead>
                    <TableHead className="text-right">LLM</TableHead>
                    <TableHead className="text-right">Compute</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {workers.map((w) => (
                    <TableRow key={`${w.worker_id}-${w.date}`}>
                      <TableCell>{w.worker_id}</TableCell>
                      <TableCell>{w.agent_type}</TableCell>
                      <TableCell className="text-right">{formatCents(w.llm_cost_cents)}</TableCell>
                      <TableCell className="text-right">{formatCents(w.compute_cost_cents)}</TableCell>
                      <TableCell className="text-right">{formatCents(w.total_cost_cents)}</TableCell>
                    </TableRow>
                  ))}
                  {workers.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-muted-foreground">
                        No worker entries for this date.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ticket">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">By Ticket</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="breakdown-table-ticket">
                <TableHeader>
                  <TableRow>
                    <TableHead>Ticket</TableHead>
                    <TableHead>Agent Type</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tickets.map((t) => (
                    <TableRow key={t.ticket_id}>
                      <TableCell>{t.ticket_id}</TableCell>
                      <TableCell>{t.agent_type}</TableCell>
                      <TableCell className="text-right">{formatCents(t.total_cost_cents)}</TableCell>
                      <TableCell>
                        <Badge variant={t.status === "completed" ? "default" : "secondary"}>
                          {t.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                  {tickets.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-muted-foreground">
                        No ticket cost data yet.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
