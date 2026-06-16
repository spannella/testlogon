import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { BookOpen, Eye, FolderTree, Search, ThumbsUp, Tag } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  publicListArticles,
  publicListCategories,
  publicListTags,
  publicSearchArticles,
  type KbArticleSummary,
} from "@/api/endpoints/knowledgeBase";
import { fmtDate, isNotEnabledError, KbNotEnabledCard } from "./kbShared";

function PortalCard({ article }: { article: KbArticleSummary }) {
  return (
    <Link
      to={`/crm/knowledge-base/portal/articles/${encodeURIComponent(article.article_id)}`}
      className="block"
    >
      <Card className="h-full transition-colors hover:border-primary">
        <CardHeader className="space-y-1">
          <CardTitle className="text-base leading-snug">{article.title}</CardTitle>
          {article.category && (
            <CardDescription className="flex items-center gap-1">
              <FolderTree className="h-3 w-3" /> {article.category}
            </CardDescription>
          )}
        </CardHeader>
        <CardContent className="space-y-2">
          {article.excerpt && (
            <p className="line-clamp-2 text-sm text-muted-foreground">{article.excerpt}</p>
          )}
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Eye className="h-3 w-3" /> {article.view_count}
            </span>
            <span className="flex items-center gap-1">
              <ThumbsUp className="h-3 w-3" /> {article.helpful_count}
            </span>
            <span className="ml-auto">{fmtDate(article.published_at)}</span>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

export default function KbPortalPage() {
  const [searchInput, setSearchInput] = useState("");
  const [query, setQuery] = useState("");
  const [categoryId, setCategoryId] = useState("");

  const categoriesQuery = useQuery({
    queryKey: ["kb", "public", "categories"],
    queryFn: publicListCategories,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const tagsQuery = useQuery({
    queryKey: ["kb", "public", "tags"],
    queryFn: () => publicListTags(20),
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const articlesQuery = useQuery({
    queryKey: ["kb", "public", "articles", { query, categoryId }],
    queryFn: () => {
      if (query.trim()) {
        return publicSearchArticles(query.trim(), { limit: 50 }).then((r) => ({
          items: r.items,
          cursor: r.cursor,
          total: r.items.length,
        }));
      }
      return publicListArticles({ category_id: categoryId || undefined, limit: 50 });
    },
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const notEnabled = useMemo(
    () =>
      isNotEnabledError(articlesQuery.error) ||
      isNotEnabledError(categoriesQuery.error),
    [articlesQuery.error, categoriesQuery.error],
  );

  if (notEnabled) {
    return (
      <div className="space-y-6">
        <PageHeader title="Help Center" description="Public knowledge base portal." />
        <KbNotEnabledCard />
      </div>
    );
  }

  const articles = articlesQuery.data?.items ?? [];
  const categories = categoriesQuery.data?.categories ?? [];
  const tags = tagsQuery.data?.tags ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-8 py-4">
      <div className="space-y-4 text-center">
        <div className="flex items-center justify-center gap-2">
          <BookOpen className="h-7 w-7 text-primary" />
          <h1 className="text-3xl font-semibold tracking-tight">Help Center</h1>
        </div>
        <p className="text-muted-foreground">
          Search our knowledge base for answers, guides, and FAQs.
        </p>
        <div className="mx-auto flex max-w-xl items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") setQuery(searchInput);
              }}
              placeholder="Search the help center…"
              className="pl-8"
            />
          </div>
          <Button onClick={() => setQuery(searchInput)}>Search</Button>
        </div>
      </div>

      {categories.length > 0 && !query && (
        <div className="flex flex-wrap items-center justify-center gap-2">
          <Button
            size="sm"
            variant={categoryId === "" ? "default" : "outline"}
            onClick={() => setCategoryId("")}
          >
            All
          </Button>
          {categories.map((c) => (
            <Button
              key={c.category_id}
              size="sm"
              variant={categoryId === c.category_id ? "default" : "outline"}
              onClick={() => setCategoryId(c.category_id)}
            >
              {c.name}
            </Button>
          ))}
        </div>
      )}

      {articlesQuery.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-36 w-full" />
          ))}
        </div>
      ) : articles.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
            <BookOpen className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              {query ? `No articles match "${query}".` : "No published articles yet."}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {articles.map((a) => (
            <PortalCard key={a.article_id} article={a} />
          ))}
        </div>
      )}

      {tags.length > 0 && (
        <div className="space-y-2">
          <p className="flex items-center justify-center gap-2 text-sm font-medium text-muted-foreground">
            <Tag className="h-4 w-4" /> Popular topics
          </p>
          <div className="flex flex-wrap justify-center gap-1">
            {tags.map((t) => (
              <Badge key={t.tag} variant="outline" className="text-xs">
                {t.tag} ({t.article_count})
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
