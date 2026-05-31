import type { DependencyGraph } from "@/api/types";

const COMPLEXITY_COLORS: Record<string, string> = {
  low: "bg-green-500",
  medium: "bg-yellow-500",
  high: "bg-orange-500",
  critical: "bg-red-500",
};

interface Props {
  graph: DependencyGraph;
  onNodeClick?: (ticketId: string) => void;
}

/**
 * Interactive DAG visualization of ticket dependencies. Nodes are grouped into
 * columns by build order; edges describe prerequisite relationships. Nodes are
 * colored by complexity. (AGENT-011)
 */
export default function DependencyGraphView({ graph, onNodeClick }: Props) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];

  const orders = Array.from(new Set(nodes.map((n) => n.order))).sort((a, b) => a - b);
  const incoming = new Map<string, string[]>();
  for (const e of edges) {
    incoming.set(e.to, [...(incoming.get(e.to) ?? []), e.from]);
  }

  return (
    <div data-testid="dependency-graph-view" className="space-y-4">
      {nodes.length === 0 ? (
        <p className="text-sm text-muted-foreground">No dependency graph available.</p>
      ) : (
        <div className="flex gap-6 overflow-x-auto pb-2">
          {orders.map((order) => (
            <div key={order} className="flex flex-col gap-3 min-w-[200px]">
              <div className="text-xs font-semibold text-muted-foreground">Order {order}</div>
              {nodes
                .filter((n) => n.order === order)
                .map((n) => (
                  <button
                    key={n.id}
                    type="button"
                    data-testid="dep-graph-node"
                    onClick={() => onNodeClick?.(n.id)}
                    className="rounded border p-3 text-left hover:bg-accent transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-block h-3 w-3 rounded-full ${
                          COMPLEXITY_COLORS[n.complexity] ?? "bg-gray-400"
                        }`}
                      />
                      <span className="text-sm font-medium truncate">{n.subject}</span>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">{n.id}</div>
                    <div className="mt-1 text-xs">
                      {n.complexity}
                      {n.status ? ` · ${n.status}` : ""}
                    </div>
                    {(incoming.get(n.id) ?? []).length > 0 && (
                      <div className="mt-1 text-[10px] text-muted-foreground">
                        depends on: {(incoming.get(n.id) ?? []).join(", ")}
                      </div>
                    )}
                  </button>
                ))}
            </div>
          ))}
        </div>
      )}
      <div className="flex gap-4 text-xs text-muted-foreground">
        {Object.entries(COMPLEXITY_COLORS).map(([level, color]) => (
          <span key={level} className="flex items-center gap-1">
            <span className={`inline-block h-2 w-2 rounded-full ${color}`} /> {level}
          </span>
        ))}
      </div>
    </div>
  );
}
