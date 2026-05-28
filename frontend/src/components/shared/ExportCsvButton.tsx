import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ExportCsvButtonProps {
  /** The data source to export. */
  source: "billing_ledger" | "contacts" | "questionnaire_responses";
  /** Additional query parameters (e.g., from_date, to_date, questionnaire_id). */
  params?: Record<string, string | number | undefined | null>;
  /** Button label. Defaults to "Export CSV". */
  label?: string;
  /** Whether the button is disabled. */
  disabled?: boolean;
}

/**
 * A reusable button that triggers a server-side CSV export download.
 *
 * Opens the export URL in the same tab, which triggers the browser's
 * native download mechanism (Content-Disposition: attachment).
 *
 * Because the endpoint requires authentication (ui_session cookie),
 * we use window.location.href to ensure cookies are sent with the request.
 */
export function ExportCsvButton({
  source,
  params = {},
  label = "Export CSV",
  disabled = false,
}: ExportCsvButtonProps) {
  const handleExport = () => {
    const searchParams = new URLSearchParams({ source });
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") {
        searchParams.set(key, String(value));
      }
    }
    // StreamingResponse with Content-Disposition: attachment
    // triggers download without navigating away from the page.
    window.location.href = `/ui/export/csv?${searchParams.toString()}`;
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleExport}
      disabled={disabled}
      data-testid="export-csv-btn"
    >
      <Download className="mr-1 h-3.5 w-3.5" />
      {label}
    </Button>
  );
}
