/**
 * PLT-003: Glossary tab — browseable/searchable API term dictionary.
 *
 * Endpoint: GET /v1/glossary (public, no auth needed when flag is on).
 * Flag gate: OPEN_BANK_PROJECT_ENABLED + GLOSSARY_ENABLED → 404 when off.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Tag, BookOpen } from "lucide-react";

import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  listGlossaryTerms,
  type GlossaryTermOut,
} from "@/api/endpoints/bankPlatform";

function fmt(ts: number) {
  return new Date(ts * 1000).toLocaleDateString();
}

export default function GlossaryTab() {
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const query = useQuery({
    queryKey: ["bank-platform", "glossary", search, cursor],
    queryFn: () => listGlossaryTerms({ search: search || undefined, cursor, limit: 50 }),
    retry: false,
  });

  const isNotEnabled =
    query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 503);

  if (isNotEnabled) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            API Glossary
          </CardTitle>
          <CardDescription>
            The glossary feature is not enabled on this instance. Set{" "}
            <code className="rounded bg-muted px-1 text-xs">OPEN_BANK_PROJECT_ENABLED=1</code> and{" "}
            <code className="rounded bg-muted px-1 text-xs">GLOSSARY_ENABLED=1</code> to activate it.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const terms = query.data?.terms ?? [];
  const nextCursor = query.data?.next_cursor;
  const count = query.data?.count ?? 0;

  return (
    <div className="flex flex-col gap-4">
      {/* Search bar */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pl-9"
          placeholder="Search terms…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setCursor(undefined);
          }}
        />
      </div>

      {/* Loading state */}
      {query.isLoading && (
        <div className="grid gap-3 sm:grid-cols-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      )}

      {/* Error state */}
      {query.isError && !isNotEnabled && (
        <Card className="border-destructive">
          <CardContent className="pt-4 text-sm text-destructive">
            Failed to load glossary: {query.error instanceof Error ? query.error.message : "Unknown error"}
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!query.isLoading && !query.isError && terms.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            {search ? `No terms matching "${search}".` : "No glossary terms defined yet."}
          </CardContent>
        </Card>
      )}

      {/* Term cards */}
      {terms.length > 0 && (
        <>
          <p className="text-sm text-muted-foreground">{count} term{count !== 1 ? "s" : ""}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            {terms.map((term) => (
              <GlossaryTermCard key={term.term_id} term={term} />
            ))}
          </div>

          {/* Pagination */}
          <div className="flex items-center gap-3">
            {cursor && (
              <Button variant="outline" size="sm" onClick={() => setCursor(undefined)}>
                First page
              </Button>
            )}
            {nextCursor && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCursor(nextCursor)}
                disabled={query.isFetching}
              >
                Load more
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function GlossaryTermCard({ term }: { term: GlossaryTermOut }) {
  const [expanded, setExpanded] = useState(false);
  const preview = term.definition.slice(0, 160);
  const isTruncated = term.definition.length > 160;

  return (
    <Card className="flex flex-col gap-0">
      <CardHeader className="pb-2">
        <CardTitle className="text-base">{term.term}</CardTitle>
        <CardDescription className="text-xs">
          Updated {fmt(term.updated_at)} · by {term.updated_by}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2 text-sm">
        <p className="text-muted-foreground leading-relaxed">
          {expanded || !isTruncated ? term.definition : preview + "…"}
        </p>
        {isTruncated && (
          <button
            className="self-start text-xs text-primary underline-offset-2 hover:underline"
            onClick={() => setExpanded((e) => !e)}
          >
            {expanded ? "Show less" : "Show more"}
          </button>
        )}
        {term.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {term.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="gap-1 text-xs">
                <Tag className="h-3 w-3" />
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
