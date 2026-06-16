import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { ChartConfig } from "@/api/endpoints/crmReports";

const PALETTE = [
  "#6366f1",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#06b6d4",
  "#a855f7",
  "#ec4899",
  "#84cc16",
];

interface ReportChartProps {
  chart: ChartConfig;
  columns: string[];
  rows: Array<Array<unknown>>;
}

function toNumber(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Renders a report's chart (bar / line / pie) from its tabular result set,
 * using the chart config's x_field / y_field to map to columns.
 */
export function ReportChart({ chart, columns, rows }: ReportChartProps) {
  const data = useMemo(() => {
    const xIdx = columns.indexOf(chart.x_field);
    const yIdx = columns.indexOf(chart.y_field);
    if (xIdx === -1 || yIdx === -1) return [];
    return rows.map((row) => ({
      name: row[xIdx] === null || row[xIdx] === undefined ? "—" : String(row[xIdx]),
      value: toNumber(row[yIdx]),
    }));
  }, [chart.x_field, chart.y_field, columns, rows]);

  if (data.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
        Chart columns ({chart.x_field} / {chart.y_field}) not found in result set.
      </div>
    );
  }

  if (chart.chart_type === "pie") {
    return (
      <ResponsiveContainer width="100%" height={320}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={110}
            label
          >
            {data.map((_, i) => (
              <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    );
  }

  if (chart.chart_type === "line") {
    return (
      <ResponsiveContainer width="100%" height={320}>
        <LineChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip />
          <Line type="monotone" dataKey="value" name={chart.y_field} stroke={PALETTE[0]} strokeWidth={2} />
        </LineChart>
      </ResponsiveContainer>
    );
  }

  // default: bar
  return (
    <ResponsiveContainer width="100%" height={320}>
      <BarChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis dataKey="name" tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip />
        <Bar dataKey="value" name={chart.y_field}>
          {data.map((_, i) => (
            <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
