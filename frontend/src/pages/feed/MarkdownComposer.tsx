import { useEffect, useMemo, useRef } from "react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { newsfeedMarkdownEnabled, newsfeedRichtextEnabled } from "@/lib/featureFlags";
import { Textarea } from "@/components/ui/textarea";

export type EditorMode = "plain" | "markdown" | "rich";

export type RichNode = {
  type: string;
  text?: string;
  attrs?: Record<string, unknown>;
  marks?: Array<{ type: string; attrs?: Record<string, unknown> }>;
  content?: RichNode[];
};

export type RichDoc = { type: "doc"; content: RichNode[] };

interface MarkdownComposerProps {
  mode: EditorMode;
  onModeChange: (mode: EditorMode) => void;
  value: string;
  onChange: (value: string) => void;
  richDoc?: RichDoc | null;
  onRichDocChange?: (doc: RichDoc | null) => void;
  placeholder: string;
  rows?: number;
}

function safeLink(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "mailto:" ? url : null;
  } catch {
    return null;
  }
}

function renderInlineMarkdown(line: string): ReactNode[] {
  const out: ReactNode[] = [];
  const regex = /(\[[^\]]+\]\([^\)]+\)|\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g;
  let last = 0;
  let idx = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(line)) !== null) {
    if (m.index > last) out.push(line.slice(last, m.index));
    const token = m[0];
    if (token.startsWith("**") && token.endsWith("**")) {
      out.push(<strong key={`b-${idx++}`}>{token.slice(2, -2)}</strong>);
    } else if (token.startsWith("*") && token.endsWith("*")) {
      out.push(<em key={`i-${idx++}`}>{token.slice(1, -1)}</em>);
    } else if (token.startsWith("`") && token.endsWith("`")) {
      out.push(<code key={`c-${idx++}`}>{token.slice(1, -1)}</code>);
    } else if (token.startsWith("[")) {
      const mm = token.match(/^\[([^\]]+)\]\(([^\)]+)\)$/);
      if (mm) {
        const label = mm[1] ?? "";
        const rawHref = mm[2] ?? "";
        const href = safeLink(rawHref.trim());
        if (href) {
          out.push(
            <a key={`a-${idx++}`} href={href} target="_blank" rel="noopener noreferrer nofollow" className="underline">
              {label}
            </a>,
          );
        } else {
          out.push(label);
        }
      } else {
        out.push(token);
      }
    }
    last = m.index + token.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

export function MarkdownPreview({ value }: { value: string }) {
  const lines = value.split(/\r?\n/);
  return (
    <div className="rounded-md border bg-muted/30 p-3 text-sm space-y-1">
      {lines.map((line, i) => {
        const t = line.trim();
        if (!t) return <div key={i} className="h-4" />;
        if (t.startsWith("- ")) return <p key={i}>• {renderInlineMarkdown(t.slice(2))}</p>;
        if (/^\d+\.\s+/.test(t)) return <p key={i}>{renderInlineMarkdown(t.replace(/^\d+\.\s+/, ""))}</p>;
        if (t.startsWith(">")) return <p key={i} className="border-l-2 pl-2 italic">{renderInlineMarkdown(t.slice(1).trim())}</p>;
        return <p key={i}>{renderInlineMarkdown(t)}</p>;
      })}
    </div>
  );
}

function collectText(node: RichNode): string {
  if (node.type === "text") return node.text ?? "";
  return (node.content ?? []).map(collectText).join("");
}

export function richDocToPlain(doc: RichDoc | null | undefined): string {
  if (!doc?.content?.length) return "";
  return doc.content.map((n) => collectText(n)).join("\n").trim();
}

function marksWrap(text: string, marks?: RichNode["marks"]): string {
  let out = text;
  for (const mark of marks ?? []) {
    if (mark.type === "bold") out = `<strong>${out}</strong>`;
    else if (mark.type === "italic") out = `<em>${out}</em>`;
    else if (mark.type === "code") out = `<code>${out}</code>`;
    else if (mark.type === "link") {
      const href = typeof mark.attrs?.href === "string" ? mark.attrs.href : "";
      const safe = safeLink(href);
      if (safe) out = `<a href="${safe}">${out}</a>`;
    }
  }
  return out;
}

function nodeToHtml(node: RichNode): string {
  if (node.type === "text") return marksWrap((node.text ?? "").replace(/</g, "&lt;").replace(/>/g, "&gt;"), node.marks);
  const children = (node.content ?? []).map(nodeToHtml).join("");
  if (node.type === "paragraph") return `<p>${children || "<br>"}</p>`;
  if (node.type === "blockquote") return `<blockquote>${children}</blockquote>`;
  if (node.type === "codeBlock") return `<pre><code>${children}</code></pre>`;
  if (node.type === "bulletList") return `<ul>${children}</ul>`;
  if (node.type === "orderedList") return `<ol>${children}</ol>`;
  if (node.type === "listItem") return `<li>${children}</li>`;
  if (node.type === "hardBreak") return "<br>";
  return children;
}

export function richDocToHtml(doc: RichDoc | null | undefined, fallback: string): string {
  if (!doc?.content?.length) return fallback ? `<p>${fallback}</p>` : "<p><br></p>";
  return doc.content.map(nodeToHtml).join("");
}

function parseInlineNode(el: ChildNode): RichNode[] {
  if (el.nodeType === Node.TEXT_NODE) {
    const t = el.textContent ?? "";
    return t ? [{ type: "text", text: t }] : [];
  }
  if (!(el instanceof HTMLElement)) return [];
  const tag = el.tagName.toLowerCase();
  if (tag === "br") return [{ type: "hardBreak" }];
  if (["strong", "b", "em", "i", "code", "a"].includes(tag)) {
    const markType = tag === "strong" || tag === "b" ? "bold" : tag === "em" || tag === "i" ? "italic" : tag === "code" ? "code" : "link";
    const attrs = markType === "link" ? { href: el.getAttribute("href") ?? "" } : undefined;
    const children = Array.from(el.childNodes).flatMap(parseInlineNode);
    return children.map((n) => ({ ...n, marks: [...(n.marks ?? []), { type: markType, ...(attrs ? { attrs } : {}) }] }));
  }
  return Array.from(el.childNodes).flatMap(parseInlineNode);
}

function parseBlock(el: HTMLElement): RichNode | null {
  const tag = el.tagName.toLowerCase();
  if (tag === "p" || tag === "div") return { type: "paragraph", content: Array.from(el.childNodes).flatMap(parseInlineNode) };
  if (tag === "blockquote") return { type: "blockquote", content: [{ type: "paragraph", content: Array.from(el.childNodes).flatMap(parseInlineNode) }] };
  if (tag === "pre") return { type: "codeBlock", content: [{ type: "text", text: el.textContent ?? "" }] };
  if (tag === "ul" || tag === "ol") {
    const listType = tag === "ul" ? "bulletList" : "orderedList";
    const items = Array.from(el.querySelectorAll(":scope > li")).map((li) => ({ type: "listItem", content: [{ type: "paragraph", content: Array.from(li.childNodes).flatMap(parseInlineNode) }] }));
    return { type: listType, content: items };
  }
  return { type: "paragraph", content: Array.from(el.childNodes).flatMap(parseInlineNode) };
}

function htmlToRichDoc(html: string): RichDoc {
  const parser = new DOMParser();
  const doc = parser.parseFromString(`<div>${html}</div>`, "text/html");
  const root = doc.body.firstElementChild;
  const content: RichNode[] = [];
  if (root) {
    for (const child of Array.from(root.children)) {
      const node = parseBlock(child as HTMLElement);
      if (node) content.push(node);
    }
  }
  if (content.length === 0) content.push({ type: "paragraph", content: [] });
  return { type: "doc", content };
}


export function RichPreview({ doc, fallback }: { doc?: RichDoc | null; fallback?: string }) {
  const html = richDocToHtml(doc, fallback ?? "");
  return <div className="rounded-md border bg-muted/30 p-3 text-sm" dangerouslySetInnerHTML={{ __html: html }} />;
}

function RichTextEditor({
  value,
  richDoc,
  onChange,
  onRichDocChange,
  placeholder,
}: {
  value: string;
  richDoc?: RichDoc | null;
  onChange: (v: string) => void;
  onRichDocChange?: (d: RichDoc | null) => void;
  placeholder: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const initialHtml = useMemo(() => richDocToHtml(richDoc, value), [richDoc, value]);

  useEffect(() => {
    if (ref.current && document.activeElement !== ref.current) {
      ref.current.innerHTML = initialHtml;
    }
  }, [initialHtml]);

  const run = (cmd: string, arg?: string) => {
    ref.current?.focus();
    document.execCommand(cmd, false, arg);
    const html = ref.current?.innerHTML ?? "";
    onRichDocChange?.(htmlToRichDoc(html));
    onChange(ref.current?.innerText ?? "");
  };

  const addLink = () => {
    const url = window.prompt("Enter link URL (https:// or mailto:)");
    if (!url) return;
    const safe = safeLink(url.trim());
    if (!safe) return;
    ref.current?.focus();
    document.execCommand("createLink", false, safe);
    const html = ref.current?.innerHTML ?? "";
    onRichDocChange?.(htmlToRichDoc(html));
    onChange(ref.current?.innerText ?? "");
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1">
        <Button type="button" size="sm" variant="ghost" onClick={() => run("bold")}>B</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => run("italic")}>I</Button>
        <Button type="button" size="sm" variant="ghost" onClick={addLink}>Link</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => run("insertUnorderedList")}>• List</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => run("insertOrderedList")}>1. List</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => run("formatBlock", "blockquote")}>Quote</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => run("formatBlock", "pre")}>Code</Button>
      </div>
      <div
        ref={ref}
        contentEditable
        suppressContentEditableWarning
        onInput={() => {
          const html = ref.current?.innerHTML ?? "";
          onRichDocChange?.(htmlToRichDoc(html));
          onChange(ref.current?.innerText ?? "");
        }}
        className="min-h-[120px] rounded-md border bg-background px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        data-placeholder={placeholder}
      />
    </div>
  );
}

export function MarkdownComposer({
  mode,
  onModeChange,
  value,
  onChange,
  richDoc,
  onRichDocChange,
  placeholder,
  rows = 4,
}: MarkdownComposerProps) {
  const markdownEnabled = newsfeedMarkdownEnabled;
  const richEnabled = newsfeedRichtextEnabled;
  const effectiveMode: EditorMode = mode === "rich" && !richEnabled ? "plain" : mode === "markdown" && !markdownEnabled ? "plain" : mode;

  useEffect(() => {
    if (effectiveMode !== mode) {
      onModeChange(effectiveMode);
    }
  }, [effectiveMode, mode, onModeChange]);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1">
        <Button type="button" size="sm" variant={effectiveMode === "plain" ? "secondary" : "ghost"} onClick={() => onModeChange("plain")}>Plain</Button>
        {markdownEnabled && (
          <Button type="button" size="sm" variant={effectiveMode === "markdown" ? "secondary" : "ghost"} onClick={() => onModeChange("markdown")}>Markdown</Button>
        )}
        {richEnabled && (
          <Button type="button" size="sm" variant={effectiveMode === "rich" ? "secondary" : "ghost"} onClick={() => onModeChange("rich")}>Rich</Button>
        )}
      </div>

      {effectiveMode === "rich" ? (
        <RichTextEditor
          value={value}
          richDoc={richDoc}
          onChange={onChange}
          onRichDocChange={onRichDocChange}
          placeholder={placeholder}
        />
      ) : (
        <Textarea placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} rows={rows} />
      )}

      {effectiveMode === "markdown" && value.trim() && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Preview</p>
          <MarkdownPreview value={value} />
        </div>
      )}
    </div>
  );
}

export function buildContentPayload(body: string, mode: EditorMode, richDoc?: RichDoc | null) {
  if (mode === "markdown" && newsfeedMarkdownEnabled) {
    return {
      body_plain: body,
      body_markdown: body,
      body_format: "markdown" as const,
      body_version: 1,
    };
  }
  if (mode === "rich" && newsfeedRichtextEnabled) {
    return {
      body_plain: body,
      body_rich: richDoc ?? { type: "doc", content: [{ type: "paragraph", content: [] }] },
      body_format: "rich" as const,
      body_version: 1,
    };
  }
  return { body };
}
