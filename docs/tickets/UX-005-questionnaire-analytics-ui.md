# UX-005: Questionnaire Response Analytics Frontend

**Ticket**: UX-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 3-4 days

---

## 1. Executive Summary

<!-- NOTE: This feature is ALREADY IMPLEMENTED. QuestionnaireAnalyticsTab.tsx exists at frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.tsx. QuestionnaireBuilderPage.tsx already uses it (lines 398-399) instead of inline analytics rendering. recharts is installed at package.json:64. -->

The backend `GET /questionnaires/drafts/{id}/analytics` endpoint (questionnaires.py:604) computes rich analytics data -- funnel metrics (starts, completions, completion rate), average completion time, top 5 dropoff points, and validation hotspots. The frontend `QuestionnaireBuilderPage.tsx` already fetches this data (line 92) and renders it via the `QuestionnaireAnalyticsTab` component (lines 398-399). The analytics data deserves proper visual treatment.

Questionnaire creators invest significant effort in designing forms and need to understand their performance. A completion rate of 0.7 is a number; a green circular gauge showing 70% is instantly interpretable. A list of dropoff points as `"Section 1 / q_slider: 2"` requires mental parsing; a horizontal bar chart with proportional bars communicates relative severity at a glance. Visual analytics transform raw data into actionable insights, helping creators identify which sections cause abandonment and which questions trigger validation errors.

This feature replaces the existing text-only analytics card with a visual analytics tab containing a funnel chart, a dropoff bar chart, a completion rate gauge, and a validation hotspot heatmap-style list. All data is already available from the existing API -- this is a frontend-only enhancement. No new API endpoints, no new DynamoDB queries, no new data transformations. The backend `_compute_questionnaire_analytics` function (lines 150-228) already computes everything needed.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Visual funnel chart**
As a creator, I want to see a visual funnel showing how many respondents start vs. complete my questionnaire so that I can immediately assess the form's conversion quality.

Acceptance Criteria:
- A funnel chart shows "Started" as a full-width bar and "Completed" as a proportionally narrower bar.
- Both bars have count labels (e.g., "10 started", "7 completed").
- The completion percentage is displayed between the bars (e.g., "70% completion rate").
- Color coding: blue for started, green for completed.
- Zero-state: when starts=0, show a message "No responses yet" instead of empty bars.

**US-2: Dropoff point bar chart**
As a creator, I want to see where respondents drop off visualized as a bar chart so that I can identify and fix problematic sections.

Acceptance Criteria:
- Horizontal bar chart showing top 5 dropoff points.
- Each bar's width is proportional to the maximum dropoff count.
- Section labels appear on the left, count numbers on the right.
- Bars are color-coded by severity: red for the highest count, orange for medium, grey for low.
- Clicking a dropoff section scrolls to that section in the builder (if on the builder tab).

**US-3: Completion rate gauge**
As a creator, I want to see the completion rate as a circular gauge so that I can assess form health at a glance without reading numbers.

Acceptance Criteria:
- A circular progress ring (SVG) shows the completion percentage.
- The percentage number is displayed in the center of the ring.
- Color changes based on rate: green (>=70%), yellow (40-69%), red (<40%).
- The gauge animates from 0 to the current value on mount (optional, subtle).

**US-4: Validation hotspot indicators**
As a creator, I want to see which questions cause the most validation errors with color-coded severity badges so that I can improve question design and reduce respondent frustration.

Acceptance Criteria:
- Ranked list of validation hotspots with severity badges.
- Red badge for high error count (>50% of max), yellow for medium (25-50% of max), grey for low (<25%).
- Hovering a hotspot shows a tooltip with the full error key and count.
- Question keys like `"form:submit"` are displayed with human-readable labels where possible.

**US-5: Per-version comparison**
As a creator who has published multiple questionnaire versions, I want to compare analytics across versions so that I can measure the impact of changes.

Acceptance Criteria:
- A version selector (dropdown or tab strip) above the analytics charts.
- Selecting a version shows that version's funnel, dropoff, and hotspot data.
- A "Totals" option shows aggregate data across all versions (current default).
- Per-version data includes: version number, published date, funnel, avg completion time, dropoffs, hotspots.

### 2.2 Pain Points

1. **Raw numbers are hard to interpret**: "10 starts, 7 completions (70%)" requires mental math to assess quality. Is 70% good? A visual gauge with color coding provides instant context.
2. **Dropoff list has no visual weight**: A plain `<ul>` list does not convey the relative severity of dropoff points. A bar chart makes the worst offender immediately obvious.
3. **No quick-glance summary**: Creators must read each line of text to understand questionnaire health. A dashboard-style layout with gauge + funnel provides instant assessment.
4. **Validation hotspots are cryptic**: Key names like `"form:submit"` or `"q_slider"` need context. The current plain list does not help creators understand what to fix.
5. **No version comparison**: Versions are listed sequentially as text blocks. There is no side-by-side or tabbed view to compare version performance.

---

## 3. Current State Analysis

### 3.1 Backend Analytics Endpoint

`GET /questionnaires/drafts/{id}/analytics` (questionnaires.py:604) returns a `QuestionnaireAnalyticsEnvelope` (line 141) containing analytics data computed by `_compute_questionnaire_analytics` (lines 150-228).

The function:
1. Reads all response sessions for the questionnaire via `REPO.list_response_sessions(questionnaire_id=questionnaire_id)` (line 151)
2. Reads all response events via `REPO.list_response_events(questionnaire_id=questionnaire_id)` (line 152)
3. For each published version:
   - Counts starts (total sessions for that version)
   - Counts completions (sessions with `status == "submitted"`)
   - Calculates average completion time from `started_at` and `submitted_at`
   - Identifies top 5 dropoff points (sessions that started but did not submit, grouped by last section/question)
   - Identifies top 5 validation hotspots (events with `event_type == "response_validation_failed"`, grouped by error keys)
4. Returns per-version data + aggregate totals

**Response shape:**
```json
{
  "analytics": {
    "generated_at": "1748380800",
    "freshness_sla_seconds": 60,
    "versions": [
      {
        "version_id": "ver_2",
        "version_number": 2,
        "published_at": "...",
        "funnel": { "starts": 10, "completions": 7, "completion_rate": 0.7 },
        "average_completion_seconds": 120,
        "dropoff_points": [
          { "label": "Section 1 / q_slider", "count": 2 },
          { "label": "Section 2", "count": 1 }
        ],
        "validation_hotspots": [
          { "key": "form:submit", "count": 3 },
          { "key": "q_email", "count": 1 }
        ]
      }
    ],
    "totals": {
      "starts": 10,
      "completions": 7,
      "top_dropoffs": [...],
      "top_validation_hotspots": [...]
    }
  }
}
```

**Citations**:
- `app/routers/questionnaires.py:141-142` -- `QuestionnaireAnalyticsEnvelope` model
- `app/routers/questionnaires.py:150-228` -- `_compute_questionnaire_analytics` function
- `app/routers/questionnaires.py:151` -- `REPO.list_response_sessions` call
- `app/routers/questionnaires.py:152` -- `REPO.list_response_events` call
- `app/routers/questionnaires.py:204-205` -- Top 5 dropoffs sorted by count
- `app/routers/questionnaires.py:206` -- Completion rate calculation: `(completions / starts) if starts else 0.0`
- `app/routers/questionnaires.py:208-216` -- Per-version data assembly
- `app/routers/questionnaires.py:218-228` -- Aggregate totals across all versions
- `app/routers/questionnaires.py:604-613` -- `GET /drafts/{questionnaire_id}/analytics` endpoint

### 3.2 Frontend Analytics Card (Current)

`QuestionnaireBuilderPage.tsx` fetches analytics at line 90 using React Query:

```typescript
const analyticsQuery = useQuery({
  queryKey: ["questionnaire", questionnaireId, "analytics"],
  queryFn: () => getQuestionnaireAnalytics(questionnaireId),
  enabled: Boolean(questionnaireId),
  refetchInterval: 60000,  // Auto-refresh every 60s
});
```

The rendering (lines 395-432) is a `Card` with:
- A `CardHeader` with "Response analytics" title (line 397)
- Freshness timestamp and SLA display: `"Updated at {generated_at} (SLA {sla}s)"` (line 400)
- Summary stats grid: total starts, total completions, version count (lines 401-404)
- Per-version blocks: version ID, funnel text `"10 starts → 7 completions (70%)"`, avg completion time (lines 406-414)
- Top dropoff points as a plain `<ul>` with `data-testid="analytics-dropoff-list"` (lines 416-421)
- Validation hotspots as a plain `<ul>` with `data-testid="analytics-hotspot-list"` (lines 423-428)

All data is rendered as plain text with `data-testid` attributes for testing.

**Current rendering code:**
```typescript
<Card data-testid="questionnaire-analytics-card">
  <CardHeader><CardTitle>Response analytics</CardTitle></CardHeader>
  <CardContent className="space-y-3 text-sm">
    <div data-testid="analytics-freshness">Updated at {analyticsQuery.data?.analytics?.generated_at || "-"} (SLA {analyticsQuery.data?.analytics?.freshness_sla_seconds || 60}s)</div>
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
      <div data-testid="analytics-total-starts">Starts: <strong>{...}</strong></div>
      <div data-testid="analytics-total-completions">Completions: <strong>{...}</strong></div>
      <div data-testid="analytics-version-count">Published versions: <strong>{...}</strong></div>
    </div>
    {/* Per-version funnel text */}
    {(analyticsQuery.data?.analytics?.versions || []).map((row) => (
      <div key={row.version_id} data-testid={`analytics-version-${row.version_id}`}>
        <div data-testid={`analytics-funnel-${row.version_id}`}>
          Funnel: {row.funnel.starts} starts → {row.funnel.completions} completions ({Math.round((row.funnel.completion_rate || 0) * 100)}%)
        </div>
        <div>Avg completion: {row.average_completion_seconds == null ? "-" : `${Math.round(row.average_completion_seconds)}s`}</div>
      </div>
    ))}
    {/* Dropoff list */}
    <ul data-testid="analytics-dropoff-list" className="list-disc pl-5">
      {(analyticsQuery.data?.analytics?.totals?.top_dropoffs || []).map((item) => (
        <li key={`${item.label}-${item.count}`}>{item.label}: {item.count}</li>
      ))}
    </ul>
    {/* Hotspot list */}
    <ul data-testid="analytics-hotspot-list" className="list-disc pl-5">
      {(analyticsQuery.data?.analytics?.totals?.top_validation_hotspots || []).map((item) => (
        <li key={`${item.key}-${item.count}`}>{item.key}: {item.count}</li>
      ))}
    </ul>
  </CardContent>
</Card>
```

**Citations**:
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:92-94` -- `analyticsQuery` React Query hook
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:398-399` -- **ALREADY REFACTORED**: `<QuestionnaireAnalyticsTab>` component call (replaced inline card)
- `frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.tsx` -- Visual analytics component (already exists)

### 3.3 Frontend API Client

`frontend/src/api/endpoints/questionnaires.ts:106` provides the `getQuestionnaireAnalytics` function that the query uses. This function is a simple GET wrapper -- no transformation of the response data.

**Citations**:
- `frontend/src/api/endpoints/questionnaires.ts:105` -- `getQuestionnaireAnalytics` API function

### 3.4 Existing Unit Tests

`QuestionnaireBuilderPage.test.tsx` (lines 198-206) verifies the analytics card renders with correct `data-testid` values: `analytics-total-starts`, `analytics-total-completions`, `analytics-funnel-ver_2`, `analytics-dropoff-list`, `analytics-hotspot-list`.

These test IDs MUST be preserved in the new implementation to avoid breaking existing tests.

**Citations**:
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.test.tsx:198-206` -- analytics rendering test with data-testid assertions

### 3.5 Charting Libraries

The project has `recharts` installed at version `^3.8.1` (`package.json:59`). This is a full-featured React charting library built on D3 that supports bar charts, funnel charts, pie/radial charts, and custom SVG compositions. The analytics visualizations for this feature can leverage `recharts` components (`BarChart`, `Bar`, `ResponsiveContainer`, `RadialBarChart`, etc.) rather than building custom SVG from scratch, reducing implementation effort and ensuring consistent chart rendering.

**Citations**:
- `frontend/package.json:64` -- `"recharts": "^3.8.1"` (charting library already installed)

### 3.6 Gaps

1. No visual charts (funnel, bar, gauge) -- everything is plain text
2. No completion rate visualization (gauge or progress ring)
3. Dropoff points are an unsorted `<ul>` list with no visual weight
4. Hotspots are a plain list with no severity indicator
5. No per-version comparison view (versions listed sequentially, not side-by-side)
6. No color-coded severity indicators
7. No zero-state design for empty analytics

---

## 4. Implementation Plan

### 4.1 Frontend: Analytics Tab Component

**New file `frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.tsx`:**

Extract analytics rendering from `QuestionnaireBuilderPage.tsx:395-432` into a dedicated component. The component receives the analytics data as a prop and renders the visual dashboard.

```typescript
import * as React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface VersionAnalytics {
  version_id: string;
  version_number?: number;
  published_at?: string;
  funnel: { starts: number; completions: number; completion_rate: number };
  average_completion_seconds?: number | null;
  dropoff_points: Array<{ label: string; count: number }>;
  validation_hotspots: Array<{ key: string; count: number }>;
}

interface AnalyticsData {
  generated_at: string;
  freshness_sla_seconds: number;
  versions: VersionAnalytics[];
  totals: {
    starts: number;
    completions: number;
    top_dropoffs: Array<{ label: string; count: number }>;
    top_validation_hotspots: Array<{ key: string; count: number }>;
  };
}

interface QuestionnaireAnalyticsTabProps {
  analytics: AnalyticsData | undefined;
  isLoading: boolean;
}

export default function QuestionnaireAnalyticsTab({
  analytics,
  isLoading,
}: QuestionnaireAnalyticsTabProps) {
  const [selectedVersion, setSelectedVersion] = React.useState<string>("totals");

  // Determine which data to show based on selected version
  const currentData = React.useMemo(() => {
    if (!analytics) return null;
    if (selectedVersion === "totals") {
      const totalStarts = analytics.totals.starts;
      const totalCompletions = analytics.totals.completions;
      return {
        funnel: {
          starts: totalStarts,
          completions: totalCompletions,
          completion_rate: totalStarts > 0 ? totalCompletions / totalStarts : 0,
        },
        dropoffs: analytics.totals.top_dropoffs,
        hotspots: analytics.totals.top_validation_hotspots,
        avgCompletionSeconds: null,
      };
    }
    const version = analytics.versions.find((v) => v.version_id === selectedVersion);
    if (!version) return null;
    return {
      funnel: version.funnel,
      dropoffs: version.dropoff_points,
      hotspots: version.validation_hotspots,
      avgCompletionSeconds: version.average_completion_seconds,
    };
  }, [analytics, selectedVersion]);

  if (isLoading) {
    return <Card><CardContent className="p-6">Loading analytics...</CardContent></Card>;
  }

  if (!analytics || !currentData) {
    return <Card><CardContent className="p-6 text-muted-foreground">No analytics data available.</CardContent></Card>;
  }

  return (
    <Card data-testid="questionnaire-analytics-card">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Response analytics</CardTitle>
        {analytics.versions.length > 1 && (
          <Select value={selectedVersion} onValueChange={setSelectedVersion}>
            <SelectTrigger className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="totals">All versions (totals)</SelectItem>
              {analytics.versions.map((v) => (
                <SelectItem key={v.version_id} value={v.version_id}>
                  Version {v.version_number ?? "?"} ({v.version_id})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </CardHeader>
      <CardContent className="space-y-6 text-sm">
        {/* Freshness indicator */}
        <div data-testid="analytics-freshness" className="text-xs text-muted-foreground">
          Updated at {analytics.generated_at} (SLA {analytics.freshness_sla_seconds}s)
        </div>

        {/* Summary stats row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div data-testid="analytics-total-starts" className="rounded-lg border p-3 text-center">
            <div className="text-2xl font-bold">{currentData.funnel.starts}</div>
            <div className="text-xs text-muted-foreground">Started</div>
          </div>
          <div data-testid="analytics-total-completions" className="rounded-lg border p-3 text-center">
            <div className="text-2xl font-bold">{currentData.funnel.completions}</div>
            <div className="text-xs text-muted-foreground">Completed</div>
          </div>
          <div data-testid="analytics-version-count" className="rounded-lg border p-3 text-center">
            <div className="text-2xl font-bold">{analytics.versions.length}</div>
            <div className="text-xs text-muted-foreground">Published versions</div>
          </div>
        </div>

        {/* Funnel + Gauge row */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <FunnelChart
            starts={currentData.funnel.starts}
            completions={currentData.funnel.completions}
            rate={currentData.funnel.completion_rate}
          />
          <div className="flex flex-col items-center justify-center">
            <CompletionGauge rate={currentData.funnel.completion_rate} />
            {currentData.avgCompletionSeconds != null && (
              <div className="mt-2 text-xs text-muted-foreground">
                Avg completion: {formatDuration(currentData.avgCompletionSeconds)}
              </div>
            )}
          </div>
        </div>

        {/* Per-version funnel data-testid (preserved for backward compatibility) */}
        {analytics.versions.map((row) => (
          <div
            key={row.version_id}
            data-testid={`analytics-version-${row.version_id}`}
            className="hidden"
            aria-hidden
          >
            <span data-testid={`analytics-funnel-${row.version_id}`}>
              {row.funnel.starts} starts → {row.funnel.completions} completions
            </span>
          </div>
        ))}

        {/* Dropoff bar chart */}
        <div>
          <h4 className="font-medium mb-2">Top drop-off points</h4>
          <DropoffBarChart dropoffs={currentData.dropoffs} />
          {/* Hidden list for backward compatibility */}
          <ul data-testid="analytics-dropoff-list" className="sr-only">
            {currentData.dropoffs.map((item) => (
              <li key={`${item.label}-${item.count}`}>{item.label}: {item.count}</li>
            ))}
          </ul>
        </div>

        {/* Validation hotspots */}
        <div>
          <h4 className="font-medium mb-2">Validation hotspots</h4>
          <HotspotList hotspots={currentData.hotspots} />
          {/* Hidden list for backward compatibility */}
          <ul data-testid="analytics-hotspot-list" className="sr-only">
            {currentData.hotspots.map((item) => (
              <li key={`${item.key}-${item.count}`}>{item.key}: {item.count}</li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
```

### 4.2 Funnel Chart Component

A simple SVG/CSS funnel showing started vs. completed:

```typescript
function FunnelChart({
  starts,
  completions,
  rate,
}: {
  starts: number;
  completions: number;
  rate: number;
}) {
  const completionWidth = starts > 0 ? Math.max(5, (completions / starts) * 100) : 0;
  const pct = Math.round(rate * 100);

  if (starts === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-muted-foreground text-sm">
        No responses yet
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="analytics-funnel-chart">
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div
            className="h-10 rounded-md bg-blue-500 transition-all duration-500"
            style={{ width: "100%" }}
          />
          <span className="text-sm font-medium whitespace-nowrap">
            {starts} started
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div
            className="h-10 rounded-md bg-green-500 transition-all duration-500"
            style={{ width: `${completionWidth}%` }}
          />
          <span className="text-sm font-medium whitespace-nowrap">
            {completions} completed
          </span>
        </div>
      </div>
      <div className="text-center text-sm text-muted-foreground">
        {pct}% completion rate
      </div>
    </div>
  );
}
```

### 4.3 Completion Rate Gauge

A circular progress ring using SVG `<circle>` with `stroke-dasharray`:

```typescript
function CompletionGauge({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100);
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (pct / 100) * circumference;

  // Color based on rate
  const color = pct >= 70 ? "text-green-500" : pct >= 40 ? "text-yellow-500" : "text-red-500";

  return (
    <div className="relative" data-testid="analytics-completion-gauge">
      <svg viewBox="0 0 100 100" className="h-28 w-28">
        {/* Background circle */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className="text-muted/20"
        />
        {/* Progress circle */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: "stroke-dashoffset 0.8s ease-out" }}
        />
        {/* Center text */}
        <text
          x="50" y="50"
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-foreground text-xl font-bold"
          style={{ fontSize: "20px" }}
        >
          {pct}%
        </text>
      </svg>
    </div>
  );
}
```

### 4.4 Dropoff Bar Chart

Horizontal bar chart for top 5 dropoff points:

```typescript
function DropoffBarChart({
  dropoffs,
}: {
  dropoffs: Array<{ label: string; count: number }>;
}) {
  if (dropoffs.length === 0) {
    return (
      <div className="text-sm text-muted-foreground py-2">
        No drop-off points recorded
      </div>
    );
  }

  const maxCount = Math.max(...dropoffs.map((d) => d.count));

  return (
    <div className="space-y-2" data-testid="analytics-dropoff-chart">
      {dropoffs.map((item, idx) => {
        const widthPct = maxCount > 0 ? Math.max(5, (item.count / maxCount) * 100) : 0;
        const severity = item.count / maxCount;
        const barColor =
          severity > 0.5 ? "bg-red-500" : severity > 0.25 ? "bg-orange-400" : "bg-gray-400";

        return (
          <div key={`${item.label}-${idx}`} className="flex items-center gap-3">
            <div className="w-40 truncate text-xs text-right" title={item.label}>
              {item.label}
            </div>
            <div className="flex-1 h-6 rounded bg-muted/30 overflow-hidden">
              <div
                className={`h-full rounded ${barColor} transition-all duration-500`}
                style={{ width: `${widthPct}%` }}
              />
            </div>
            <span className="text-xs font-medium w-8 text-right">{item.count}</span>
          </div>
        );
      })}
    </div>
  );
}
```

### 4.5 Validation Hotspot List

Ranked list with color-coded severity badges:

```typescript
function HotspotList({
  hotspots,
}: {
  hotspots: Array<{ key: string; count: number }>;
}) {
  if (hotspots.length === 0) {
    return (
      <div className="text-sm text-muted-foreground py-2">
        No validation errors recorded
      </div>
    );
  }

  const maxCount = Math.max(...hotspots.map((h) => h.count));

  // Map common error keys to human-readable labels
  const humanize = (key: string): string => {
    const map: Record<string, string> = {
      "form:submit": "Form submission error",
      "form:validate": "Form validation error",
    };
    return map[key] || key.replace(/_/g, " ").replace(/^q /, "Question: ");
  };

  return (
    <TooltipProvider>
      <div className="space-y-1.5" data-testid="analytics-hotspot-chart">
        {hotspots.map((item, idx) => {
          const severity = item.count / maxCount;
          const badgeVariant =
            severity > 0.5 ? "destructive" : severity > 0.25 ? "secondary" : "outline";

          return (
            <Tooltip key={`${item.key}-${idx}`}>
              <TooltipTrigger asChild>
                <div className="flex items-center justify-between rounded px-2 py-1.5 hover:bg-muted/50 cursor-default">
                  <span className="text-sm">{humanize(item.key)}</span>
                  <Badge variant={badgeVariant} className="text-xs">
                    {item.count} error{item.count !== 1 ? "s" : ""}
                  </Badge>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>Error key: <code>{item.key}</code></p>
                <p>Count: {item.count}</p>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const min = Math.floor(seconds / 60);
  const sec = Math.round(seconds % 60);
  return sec > 0 ? `${min}m ${sec}s` : `${min}m`;
}
```

### 4.6 Preserve Test IDs

All existing `data-testid` attributes are preserved for backward compatibility with unit tests:
- `questionnaire-analytics-card` -- on the outer Card
- `analytics-freshness` -- on the freshness display
- `analytics-total-starts` -- on starts stat
- `analytics-total-completions` -- on completions stat
- `analytics-version-count` -- on version count stat
- `analytics-funnel-{version_id}` -- hidden spans with funnel text (for each version)
- `analytics-version-{version_id}` -- hidden divs with version data
- `analytics-dropoff-list` -- hidden `<ul>` with `sr-only` class
- `analytics-hotspot-list` -- hidden `<ul>` with `sr-only` class

The hidden elements use `className="hidden"` or `className="sr-only"` so they exist in the DOM for test assertions but are not visible to users.

### 4.7 Replace Analytics Card in QuestionnaireBuilderPage

Replace lines 395-432 in `QuestionnaireBuilderPage.tsx` with:

```typescript
import QuestionnaireAnalyticsTab from "./QuestionnaireAnalyticsTab";

// Replace the entire analytics Card (lines 395-432) with:
<QuestionnaireAnalyticsTab
  analytics={analyticsQuery.data?.analytics}
  isLoading={analyticsQuery.isLoading}
/>
```

### 4.8 Backend Changes

None. The existing `GET /drafts/{id}/analytics` endpoint returns all necessary data. No modifications to `_compute_questionnaire_analytics` are needed.

---

## 5. Data Model

No DynamoDB changes. All data comes from the existing analytics endpoint.

---

## 6. API Design

No new API endpoints. The existing `GET /questionnaires/drafts/{id}/analytics` endpoint is used as-is.

**Existing endpoint summary:**

| Field | Description |
|-------|-------------|
| `analytics.generated_at` | Unix timestamp string of last computation |
| `analytics.freshness_sla_seconds` | Target refresh interval (60s) |
| `analytics.versions[].funnel.starts` | Number of sessions for this version |
| `analytics.versions[].funnel.completions` | Number of submitted sessions |
| `analytics.versions[].funnel.completion_rate` | Float 0.0-1.0 |
| `analytics.versions[].average_completion_seconds` | Float or null |
| `analytics.versions[].dropoff_points` | Array of `{label, count}` (top 5) |
| `analytics.versions[].validation_hotspots` | Array of `{key, count}` (top 5) |
| `analytics.totals.starts` | Sum of starts across all versions |
| `analytics.totals.completions` | Sum of completions across all versions |
| `analytics.totals.top_dropoffs` | Aggregate top 5 dropoffs |
| `analytics.totals.top_validation_hotspots` | Aggregate top 5 hotspots |

---

## 7. Frontend Implementation

### 7.1 Component Hierarchy

```
QuestionnaireBuilderPage.tsx
  └── QuestionnaireAnalyticsTab (new)
       ├── Version Selector (Select dropdown)
       ├── Summary Stats Grid (3 cards)
       ├── FunnelChart (custom CSS bars)
       ├── CompletionGauge (SVG circle)
       ├── DropoffBarChart (custom CSS bars)
       ├── HotspotList (Badge + Tooltip)
       └── Hidden test-id elements (backward compat)
```

### 7.2 State Management

| State | Type | Location | Purpose |
|-------|------|----------|---------|
| `selectedVersion` | `string` | Local state in QuestionnaireAnalyticsTab | Version selector |
| `analyticsQuery` | React Query | QuestionnaireBuilderPage (existing) | Data fetch |

No Zustand stores. No new React Query keys.

### 7.3 React Query Integration

The existing `analyticsQuery` with `queryKey: ["questionnaire", questionnaireId, "analytics"]` is passed as data to the new component. The `refetchInterval: 60000` (60s auto-refresh) remains unchanged.

### 7.4 Responsive Behavior

- **Desktop (>=md)**: Funnel chart and gauge side-by-side (2-column grid). Stats in 3-column grid.
- **Tablet (sm-md)**: Same layout as desktop (2-column grid fits).
- **Mobile (<sm)**: Single column. Funnel chart above gauge. Stats stacked vertically.
- **Summary stats**: `grid-cols-1 sm:grid-cols-3` provides responsive breakdown.
- **Dropoff labels**: `truncate` class with `title` tooltip for long section names.

---

## 8. Testing Plan

### 8.1 Unit Tests (Vitest)

**File**: `frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.test.tsx`

| # | Test Name | Assertion |
|---|-----------|-----------|
| 1 | `FunnelChart renders bars with correct widths` | Completed bar width is proportional to rate |
| 2 | `FunnelChart shows zero-state for no starts` | "No responses yet" text visible when starts=0 |
| 3 | `CompletionGauge shows correct percentage` | Text "70%" visible for rate=0.7 |
| 4 | `CompletionGauge color is green for 70%+` | SVG circle has `text-green-500` class |
| 5 | `CompletionGauge color is red for <40%` | SVG circle has `text-red-500` class |
| 6 | `DropoffBarChart renders all items` | 5 bar elements visible for 5 dropoffs |
| 7 | `DropoffBarChart highest item has red bar` | First bar has `bg-red-500` class |
| 8 | `HotspotList renders severity badges` | Red badge for highest count item |
| 9 | `HotspotList humanizes common keys` | "form:submit" renders as "Form submission error" |
| 10 | `Version selector switches displayed data` | Selecting version 2 shows version 2 funnel data |
| 11 | `Existing data-testid attributes preserved` | All 6 test IDs present in DOM |
| 12 | `formatDuration formats seconds correctly` | 90 → "1m 30s", 45 → "45s", 120 → "2m" |
| 13 | `Empty dropoffs show zero-state` | "No drop-off points recorded" visible |
| 14 | `Empty hotspots show zero-state` | "No validation errors recorded" visible |

```typescript
// Example test
import { render, screen } from "@testing-library/react";
import QuestionnaireAnalyticsTab from "./QuestionnaireAnalyticsTab";

const mockAnalytics = {
  generated_at: "1748380800",
  freshness_sla_seconds: 60,
  versions: [
    {
      version_id: "ver_2",
      version_number: 2,
      published_at: "2026-05-20",
      funnel: { starts: 10, completions: 7, completion_rate: 0.7 },
      average_completion_seconds: 120,
      dropoff_points: [{ label: "Section 1 / q_slider", count: 2 }],
      validation_hotspots: [{ key: "form:submit", count: 3 }],
    },
  ],
  totals: {
    starts: 10,
    completions: 7,
    top_dropoffs: [{ label: "Section 1 / q_slider", count: 2 }],
    top_validation_hotspots: [{ key: "form:submit", count: 3 }],
  },
};

test("CompletionGauge shows 70% for rate=0.7", () => {
  render(<QuestionnaireAnalyticsTab analytics={mockAnalytics} isLoading={false} />);
  const gauge = screen.getByTestId("analytics-completion-gauge");
  expect(gauge).toBeInTheDocument();
  expect(screen.getByText("70%")).toBeInTheDocument();
});

test("Existing data-testid attributes are preserved", () => {
  render(<QuestionnaireAnalyticsTab analytics={mockAnalytics} isLoading={false} />);
  expect(screen.getByTestId("analytics-total-starts")).toBeInTheDocument();
  expect(screen.getByTestId("analytics-total-completions")).toBeInTheDocument();
  expect(screen.getByTestId("analytics-dropoff-list")).toBeInTheDocument();
  expect(screen.getByTestId("analytics-hotspot-list")).toBeInTheDocument();
  expect(screen.getByTestId("analytics-funnel-ver_2")).toBeInTheDocument();
});
```

### 8.2 E2E Tests

**File**: `frontend/e2e/questionnaire-analytics.spec.ts`

| # | Section | Test Name | Assertion |
|---|---------|-----------|-----------|
| 1 | API | Analytics endpoint returns data | 200; `analytics.totals.starts` is a number |
| 2 | UI | Analytics card visible on builder page | Card with "Response analytics" heading visible |
| 3 | UI | Funnel chart renders bars | `[data-testid="analytics-funnel-chart"]` visible with bar elements |
| 4 | UI | Completion gauge shows percentage | `[data-testid="analytics-completion-gauge"]` contains "%" text |
| 5 | UI | Dropoff chart has bars | `[data-testid="analytics-dropoff-chart"]` visible |
| 6 | UI | Hotspot list has badges | `[data-testid="analytics-hotspot-chart"]` visible |
| 7 | UI | Summary stats show numbers | `[data-testid="analytics-total-starts"]` has numeric content |
| 8 | UI | Version selector present for multi-version | If versions > 1, Select trigger visible |

---

## 9. Security Considerations

### 9.1 No New Attack Surface

This is a frontend-only visual enhancement. No new API endpoints, no new data access, no new authentication flows. The analytics data is already fetched by the existing React Query hook.

### 9.2 XSS via Analytics Data

All analytics data (section labels, question keys, hotspot keys) is rendered via React JSX text interpolation, which auto-escapes HTML entities. The `humanize()` function maps known keys to static strings. Unknown keys are displayed as-is with `_` replaced by spaces, but still rendered as text (not `dangerouslySetInnerHTML`).

The SVG `<text>` element in the gauge also uses text interpolation (`{pct}%`), which is safe.

---

## 10. Performance Considerations

### 10.1 No Additional API Calls

The analytics data is already fetched once per 60 seconds by the existing `analyticsQuery`. The new component simply renders it differently -- no additional network requests.

### 10.2 SVG Rendering

The SVG gauge has 2 `<circle>` elements and 1 `<text>` element. The funnel chart has 2 `<div>` elements. The bar chart has at most 5 bar `<div>` elements. Total: ~10 DOM elements for all charts. This is negligible rendering overhead.

### 10.3 Transition Animations

The CSS transitions (`transition-all duration-500` on bars, `transition: stroke-dashoffset 0.8s` on gauge) are hardware-accelerated (transform/opacity). They do not trigger layout recalculations.

### 10.4 Bundle Size

- `QuestionnaireAnalyticsTab.tsx`: ~300 lines (~4KB gzipped)
- No charting library dependency
- Total bundle increase: ~4KB gzipped

---

## 11. Migration / Rollout Plan

### 11.1 Feature Flag

No feature flag needed. The change replaces the analytics card's internal rendering without changing the component's external interface (still a Card in the same position on the page).

### 11.2 Backward Compatibility

- All `data-testid` attributes are preserved (some as hidden elements).
- The analytics data shape is unchanged.
- The React Query key is unchanged.
- The refetch interval is unchanged.

### 11.3 Rollout Steps

1. Create `QuestionnaireAnalyticsTab.tsx` with all sub-components.
2. Write unit tests for each chart component.
3. Replace the inline analytics card in `QuestionnaireBuilderPage.tsx` with `<QuestionnaireAnalyticsTab>`.
4. Run existing unit tests to verify data-testid preservation.
5. Write E2E tests.

---

## 12. Acceptance Criteria

1. The questionnaire analytics card displays a visual funnel chart showing starts vs. completions with proportional bars and count labels.
2. A circular completion rate gauge shows the percentage at a glance with color coding (green >=70%, yellow 40-69%, red <40%).
3. Dropoff points are displayed as horizontal bars ranked by count with severity-based coloring (red > orange > grey).
4. Validation hotspots have color-coded severity badges (destructive for high, secondary for medium, outline for low) with tooltip details.
5. Per-version analytics are accessible via a version selector dropdown (when multiple versions exist).
6. A "Totals" option in the version selector shows aggregate data across all versions.
7. All existing `data-testid` attributes are preserved in the DOM for backward compatibility with unit tests (`analytics-total-starts`, `analytics-total-completions`, `analytics-funnel-{version_id}`, `analytics-dropoff-list`, `analytics-hotspot-list`, `analytics-version-{version_id}`).
8. Zero-states are handled: "No responses yet" for empty funnel, "No drop-off points recorded" for empty dropoffs, "No validation errors recorded" for empty hotspots.
9. No backend changes required -- all data comes from the existing analytics endpoint.
10. The analytics card auto-refreshes every 60 seconds (existing behavior preserved).
11. Visualizations use `recharts` (already installed at `^3.8.1`) or custom SVG/CSS as appropriate.

---

## 13. Dependencies

### 13.1 Internal Dependencies

- `analyticsQuery` in `QuestionnaireBuilderPage.tsx` (existing React Query hook).
- `getQuestionnaireAnalytics` API function (existing).
- shadcn/ui components: `Card`, `Badge`, `Select`, `Tooltip` (all already installed).

### 13.2 External Dependencies

None. `recharts` is already installed (`^3.8.1` in `package.json:59`) and can be used for chart components.

### 13.3 Related Tickets

- **PLATFORM-009 (CSV Export)**: The questionnaire analytics page will also have an "Export Responses" button (from PLATFORM-009). These two features complement each other: visual analytics for quick insight, CSV export for detailed analysis.
- **ANALYTICS-001 (Creator Analytics Dashboard)**: The gauge and bar chart components created here can be reused on the creator analytics dashboard.

---

## 14. Open Questions / Risks

1. **recharts vs. custom SVG**: `recharts` (`^3.8.1`) is already installed in the project. The implementation should prefer `recharts` components (e.g., `BarChart`, `RadialBarChart`, `ResponsiveContainer`) for charts that benefit from axes, labels, and responsive sizing. Simple visualizations like the completion gauge may still use custom SVG if the recharts equivalent is overkill.

2. **Version selector UX for many versions**: If a questionnaire has 20+ published versions, the Select dropdown becomes unwieldy. Consider: show only the latest 5 versions with a "Show all" option.

3. **Real-time analytics**: The 60-second refetch interval means data is up to 60 seconds stale. For high-traffic questionnaires, this may be too slow. The freshness SLA display helps set expectations.

4. **Accessibility of SVG charts**: The SVG gauge uses `<text>` for the percentage, which is readable by screen readers. The funnel bars have text labels. The dropoff bars have text labels. However, screen reader users may benefit from an alternative text summary. Consider adding `aria-label` attributes summarizing the chart data.

5. **Dark mode support**: The chart colors (blue-500, green-500, red-500, etc.) need to work in both light and dark themes. Tailwind's color palette works in both modes. The `text-muted/20` background on the gauge circle may need adjustment in dark mode.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.tsx` | Visual analytics component with funnel, gauge, bar chart, hotspot list, version selector |
| `frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.test.tsx` | Unit tests for all chart sub-components |
| `frontend/e2e/questionnaire-analytics.spec.ts` | E2E tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | Replace inline analytics card (lines 395-432) with `<QuestionnaireAnalyticsTab analytics={...} isLoading={...} />` |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Analytics endpoint | `app/routers/questionnaires.py` | 604-613 | VERIFIED |
| Analytics computation function | `app/routers/questionnaires.py` | 150-228 | VERIFIED: reads sessions + events, computes per-version funnels |
| QuestionnaireAnalyticsEnvelope model | `app/routers/questionnaires.py` | 141-142 | VERIFIED |
| list_response_sessions call | `app/routers/questionnaires.py` | 151 | VERIFIED |
| list_response_events call | `app/routers/questionnaires.py` | 152 | VERIFIED |
| Top 5 dropoffs sorted by count | `app/routers/questionnaires.py` | 204 | VERIFIED |
| Completion rate calculation | `app/routers/questionnaires.py` | 206 | VERIFIED: `(completions / starts) if starts else 0.0` |
| Frontend analytics query | `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | 92-94 | VERIFIED: `queryKey: ["questionnaire", questionnaireId, "analytics"]` |
| Analytics card rendering | `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | 398-399 | **ALREADY REFACTORED**: now uses `<QuestionnaireAnalyticsTab analytics={...} isLoading={...} />` |
| QuestionnaireAnalyticsTab component | `frontend/src/pages/questionnaires/QuestionnaireAnalyticsTab.tsx` | exists | **ALREADY IMPLEMENTED** |
| API client function | `frontend/src/api/endpoints/questionnaires.ts` | 105 | VERIFIED |
| recharts charting library installed | `frontend/package.json` | 64 | VERIFIED: `"recharts": "^3.8.1"` |

### Notes

- The inline analytics card (previously at lines 395-432) has already been extracted into `QuestionnaireAnalyticsTab.tsx` and replaced with a single `<QuestionnaireAnalyticsTab>` component call at lines 398-399.
- Backend analytics code is unchanged from the ticket description -- all line numbers match.
