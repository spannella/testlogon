import { useEffect, useState, useCallback } from "react";
import { bulkPayoutTools } from "@/api/endpoints/bulkPayoutTools";
import type {
  BulkKind,
  BulkEligibleItem,
  BulkBatchOut,
} from "@/api/types";

function fmtCents(c: number): string {
  return `$${(c / 100).toFixed(2)}`;
}

export default function BulkPayoutConsole() {
  const [kind, setKind] = useState<BulkKind>("payout");
  const [eligible, setEligible] = useState<BulkEligibleItem[]>([]);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [preview, setPreview] = useState<BulkBatchOut | null>(null);
  const [result, setResult] = useState<BulkBatchOut | null>(null);
  const [batches, setBatches] = useState<BulkBatchOut[]>([]);
  const [detail, setDetail] = useState<BulkBatchOut | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadEligible = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await bulkPayoutTools.listEligible(kind);
      setEligible(rows);
      setSelected({});
      setPreview(null);
      setResult(null);
    } catch (e: any) {
      setError(e?.message ?? "Failed to load eligible items");
    } finally {
      setLoading(false);
    }
  }, [kind]);

  const loadBatches = useCallback(async () => {
    try {
      setBatches(await bulkPayoutTools.listBatches());
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    loadEligible();
  }, [loadEligible]);

  useEffect(() => {
    loadBatches();
  }, [loadBatches]);

  const selectedIds = (): string[] =>
    eligible.filter((e) => selected[e.ref_id]).map((e) => e.ref_id);

  const toggle = (refId: string) =>
    setSelected((s) => ({ ...s, [refId]: !s[refId] }));

  const toggleAll = () => {
    const ids = selectedIds();
    if (ids.length === eligible.length) {
      setSelected({});
    } else {
      const all: Record<string, boolean> = {};
      eligible.forEach((e) => (all[e.ref_id] = true));
      setSelected(all);
    }
  };

  const doPreview = async () => {
    const ids = selectedIds();
    if (ids.length === 0) {
      setError("Select at least one item");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const p = await bulkPayoutTools.preview({ kind, ref_ids: ids });
      setPreview(p);
      setResult(null);
    } catch (e: any) {
      setError(e?.message ?? "Preview failed");
    } finally {
      setLoading(false);
    }
  };

  const doExecute = async () => {
    if (!preview) return;
    setLoading(true);
    setError(null);
    try {
      const r = await bulkPayoutTools.execute({ batch_id: preview.batch_id });
      setResult(r);
      setPreview(null);
      await loadEligible();
      await loadBatches();
    } catch (e: any) {
      setError(e?.message ?? "Execute failed");
    } finally {
      setLoading(false);
    }
  };

  const openDetail = async (batchId: string) => {
    try {
      setDetail(await bulkPayoutTools.getBatch(batchId));
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="bulk-payout-console" style={{ padding: 16 }}>
      <h1>Bulk Payout &amp; Refund Tools</h1>

      <div className="kind-picker" style={{ marginBottom: 12 }}>
        <label>
          <input
            type="radio"
            name="kind"
            checked={kind === "payout"}
            onChange={() => setKind("payout")}
          />{" "}
          Payouts
        </label>{" "}
        <label>
          <input
            type="radio"
            name="kind"
            checked={kind === "refund"}
            onChange={() => setKind("refund")}
          />{" "}
          Refunds
        </label>{" "}
        <button onClick={loadEligible} disabled={loading}>
          Reload
        </button>
      </div>

      {error && (
        <div className="error" role="alert" style={{ color: "red" }}>
          {error}
        </div>
      )}

      <section className="eligible-section">
        <h2>Eligible {kind === "payout" ? "Payouts" : "Refunds"}</h2>
        {eligible.length === 0 ? (
          <p data-testid="no-eligible">No eligible items.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label="select all"
                    checked={
                      selectedIds().length === eligible.length &&
                      eligible.length > 0
                    }
                    onChange={toggleAll}
                  />
                </th>
                <th>Ref</th>
                <th>Recipient</th>
                <th>Amount</th>
              </tr>
            </thead>
            <tbody>
              {eligible.map((e) => (
                <tr key={e.ref_id} data-testid={`eligible-${e.ref_id}`}>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`select ${e.ref_id}`}
                      checked={!!selected[e.ref_id]}
                      onChange={() => toggle(e.ref_id)}
                    />
                  </td>
                  <td>{e.ref_id}</td>
                  <td>{e.recipient}</td>
                  <td>{fmtCents(e.amount_cents)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <button onClick={doPreview} disabled={loading} data-testid="preview-btn">
          Preview ({selectedIds().length})
        </button>
      </section>

      {preview && (
        <section className="preview-section" data-testid="preview-section">
          <h2>Preview</h2>
          <p>
            Items: {preview.item_count} | Eligible:{" "}
            {(preview.items ?? []).filter((i) => i.status === "pending").length} |
            Ineligible:{" "}
            {(preview.items ?? []).filter((i) => i.status === "skipped").length} | Total:{" "}
            <span data-testid="preview-total">{fmtCents(preview.total_cents)}</span>
          </p>
          <table>
            <tbody>
              {(preview.items ?? []).map((i) => (
                <tr key={i.ref_id}>
                  <td>{i.ref_id}</td>
                  <td>{fmtCents(i.amount_cents)}</td>
                  <td>{i.status}</td>
                  <td>{i.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button onClick={doExecute} disabled={loading} data-testid="execute-btn">
            Execute Batch
          </button>
        </section>
      )}

      {result && (
        <section className="result-section" data-testid="result-section">
          <h2>Results</h2>
          <p>
            Status: <span data-testid="result-status">{result.status}</span> |
            Success:{" "}
            <span data-testid="result-success">{result.success_count}</span> |
            Failed:{" "}
            <span data-testid="result-failure">{result.failure_count}</span>
          </p>
          <table>
            <tbody>
              {(result.items ?? []).map((i) => (
                <tr key={i.ref_id}>
                  <td>{i.ref_id}</td>
                  <td>{fmtCents(i.amount_cents)}</td>
                  <td>{i.status}</td>
                  <td>{i.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="history-section">
        <h2>Batch History</h2>
        <button onClick={loadBatches}>Refresh</button>
        {batches.length === 0 ? (
          <p>No batches yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Batch</th>
                <th>Kind</th>
                <th>Status</th>
                <th>Items</th>
                <th>Total</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {batches.map((b) => (
                <tr key={b.batch_id} data-testid={`batch-${b.batch_id}`}>
                  <td>{b.batch_id}</td>
                  <td>{b.kind}</td>
                  <td>{b.status}</td>
                  <td>{b.item_count}</td>
                  <td>{fmtCents(b.total_cents)}</td>
                  <td>
                    <button onClick={() => openDetail(b.batch_id)}>View</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {detail && (
        <section className="detail-drawer" data-testid="detail-drawer">
          <h2>Batch {detail.batch_id}</h2>
          <button onClick={() => setDetail(null)}>Close</button>
          <p>
            {detail.kind} | {detail.status} | success {detail.success_count} /
            failed {detail.failure_count}
          </p>
          <table>
            <tbody>
              {(detail.items ?? []).map((i) => (
                <tr key={i.ref_id}>
                  <td>{i.ref_id}</td>
                  <td>{fmtCents(i.amount_cents)}</td>
                  <td>{i.status}</td>
                  <td>{i.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
