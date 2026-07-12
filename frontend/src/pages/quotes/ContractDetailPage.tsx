import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, Loader2 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/api/client";
import {
  getContract,
  transitionContractStage,
  type ContractStage,
} from "@/api/endpoints/quotes";
import { NotEnabledCard } from "./NotEnabledCard";
import {
  CONTRACT_TRANSITIONS,
  contractStageVariant,
  fmtDate,
  fmtDateTime,
  formatCents,
  isNotEnabled,
} from "./quotesUtils";

export default function ContractDetailPage() {
  const { contractId = "" } = useParams();
  const qc = useQueryClient();

  const contractQuery = useQuery({
    queryKey: ["contracts", "detail", contractId],
    queryFn: () => getContract(contractId),
    retry: false,
    enabled: !!contractId,
  });

  const contract = contractQuery.data;

  const stageMut = useMutation({
    mutationFn: (stage: ContractStage) => transitionContractStage(contractId, stage),
    onSuccess: (_d, stage) => {
      toast.success(`Contract marked ${stage}`);
      qc.invalidateQueries({ queryKey: ["contracts"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Stage change failed"),
  });

  if (contractQuery.isError && isNotEnabled(contractQuery.error)) {
    return (
      <div className="space-y-6">
        <BackLink />
        <NotEnabledCard feature="Contracts" />
      </div>
    );
  }

  if (contractQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (contractQuery.isError || !contract) {
    return (
      <div className="space-y-6">
        <BackLink />
        <Card>
          <CardContent className="py-16 text-center text-muted-foreground">
            Contract not found.
          </CardContent>
        </Card>
      </div>
    );
  }

  const nextStages = CONTRACT_TRANSITIONS[contract.stage] ?? [];
  const addr = contract.billing_address || {};
  const hasAddr = Object.values(addr).some((v) => v);

  return (
    <div className="space-y-6">
      <BackLink />
      <PageHeader
        title={contract.title}
        description={`${contract.contract_number} · created ${fmtDate(contract.created_at)}`}
        actions={
          <Badge variant={contractStageVariant(contract.stage)} className="capitalize">
            {contract.stage}
          </Badge>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <Field label="Value" value={formatCents(contract.value_cents, contract.currency)} />
              <Field label="Currency" value={contract.currency.toUpperCase()} />
              <Field label="Start date" value={fmtDate(contract.start_date)} />
              <Field label="End date" value={fmtDate(contract.end_date)} />
              <Field label="Renewal notice" value={`${contract.renewal_notice_days} days`} />
              <Field label="Renewal notified" value={fmtDateTime(contract.renewal_notified_at)} />
              {contract.aos_quote_id ? (
                <Field
                  label="Source quote"
                  value={
                    <Link
                      className="underline"
                      to={`/crm/quotes/${contract.aos_quote_id}`}
                    >
                      {contract.aos_quote_id}
                    </Link>
                  }
                />
              ) : null}
            </CardContent>
          </Card>

          {contract.description ? (
            <Card>
              <CardHeader>
                <CardTitle>Description</CardTitle>
              </CardHeader>
              <CardContent className="whitespace-pre-wrap text-sm text-muted-foreground">
                {contract.description}
              </CardContent>
            </Card>
          ) : null}

          {hasAddr ? (
            <Card>
              <CardHeader>
                <CardTitle>Billing address</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                <div>{addr.street}</div>
                <div>
                  {[addr.city, addr.state, addr.postal_code].filter(Boolean).join(", ")}
                </div>
                <div>{addr.country}</div>
              </CardContent>
            </Card>
          ) : null}
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Lifecycle</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {nextStages.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  This contract is in a terminal stage.
                </p>
              ) : (
                <div className="flex flex-col gap-2">
                  {nextStages.map((s) => (
                    <Button
                      key={s}
                      variant="outline"
                      size="sm"
                      className="capitalize"
                      disabled={stageMut.isPending}
                      onClick={() => stageMut.mutate(s)}
                    >
                      Mark {s}
                    </Button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/crm/contracts"
      className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="mr-1 h-4 w-4" /> Back to contracts
    </Link>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="text-sm font-medium">{value}</div>
    </div>
  );
}
