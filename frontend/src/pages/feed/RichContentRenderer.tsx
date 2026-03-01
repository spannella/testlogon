import { useEffect, useMemo, useState } from "react";
import { richDocToHtml, type RichDoc } from "./MarkdownComposer";
import { reportNewsfeedRendererEvent } from "@/lib/newsfeedTelemetry";

type BodyFormat = "plain" | "markdown" | "rich";
const KNOWN_FORMATS: ReadonlySet<string> = new Set(["plain", "markdown", "rich"]);

interface RichContentRendererProps {
  body?: string;
  bodyPlain?: string;
  bodyMarkdown?: string;
  bodyMarkdownHtml?: string;
  bodyRich?: Record<string, unknown> | null;
  bodyFormat?: BodyFormat | string;
  className?: string;
}

const COLLAPSE_CHAR_THRESHOLD = 380;
const COLLAPSE_LINE_THRESHOLD = 8;
const COLLAPSED_MAX_HEIGHT_PX = 180;

function plainTextFromProps(props: RichContentRendererProps): string {
  return props.bodyPlain ?? props.body ?? props.bodyMarkdown ?? "";
}

function markdownHtmlFromProps(props: RichContentRendererProps): string {
  if (props.bodyMarkdownHtml?.trim()) return props.bodyMarkdownHtml;
  const text = props.bodyMarkdown ?? props.bodyPlain ?? props.body ?? "";
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => `<p>${line.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</p>`)
    .join("");
}

export function RichContentRenderer({ className = "", ...props }: RichContentRendererProps) {
  const baseClass = `text-sm whitespace-pre-wrap ${className}`.trim();
  const plain = plainTextFromProps(props);

  const shouldCollapse = useMemo(() => {
    const text = plain.trim();
    if (!text) return false;
    const lineCount = text.split(/\r?\n/).length;
    return text.length > COLLAPSE_CHAR_THRESHOLD || lineCount > COLLAPSE_LINE_THRESHOLD;
  }, [plain]);

  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    setExpanded(false);
  }, [plain, props.bodyFormat, props.bodyMarkdownHtml]);

  const contentNode = (() => {
    try {
      const rawFormat = String(props.bodyFormat ?? "plain");
      const format = KNOWN_FORMATS.has(rawFormat) ? props.bodyFormat : "plain";
      if (!KNOWN_FORMATS.has(rawFormat) && props.bodyFormat) {
        reportNewsfeedRendererEvent("unsupported_format", rawFormat);
      }
      if (format === "rich" && props.bodyRich) {
        const richHtml = richDocToHtml((props.bodyRich as RichDoc) ?? null, plain);
        return <div className={baseClass} dangerouslySetInnerHTML={{ __html: richHtml }} />;
      }
      if (format === "markdown") {
        const markdownHtml = markdownHtmlFromProps(props);
        return <div className={baseClass} dangerouslySetInnerHTML={{ __html: markdownHtml }} />;
      }
      return <p className={baseClass}>{plain}</p>;
    } catch {
      reportNewsfeedRendererEvent("render_exception", String(props.bodyFormat ?? "plain"));
      return <p className={baseClass}>{plain}</p>;
    }
  })();

  if (!shouldCollapse) {
    return contentNode;
  }

  return (
    <div className="space-y-1.5">
      <div
        className={expanded ? "" : "overflow-hidden"}
        style={expanded ? undefined : { maxHeight: `${COLLAPSED_MAX_HEIGHT_PX}px` }}
        aria-expanded={expanded}
      >
        {contentNode}
      </div>
      <button
        type="button"
        className="text-xs font-medium text-muted-foreground hover:text-foreground"
        onClick={() => setExpanded((v) => !v)}
        aria-label={expanded ? "Collapse content" : "Expand content"}
      >
        {expanded ? "Show less" : "Show more"}
      </button>
    </div>
  );
}
