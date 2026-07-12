import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { BookOpen, Eye, FolderTree, Plus, Search, ThumbsUp, Tag } from "lucide-react";

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
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  listArticles,
  listCategories,
  listPopularTags,
  searchArticles,
  type KbArticleSummary,
} from "@/api/endpoints/knowledgeBase";
import { isNotEnabledError, KbNotEnabledCard, fmtDate, StatusBadge } from "./kbShared";

function ArticleCard({ article }: { article: KbArticleSummary }) {
  return (
    <Link
      to={`/crm/knowledge-base/articles/${encodeURIComponent(article.article_id)}`}
      className="block"
    >
      <Card className="h-full transition-colors hover:border-primary">
        <CardHeader className="space-y-1">
          <div className="flex items-start justify-between gap-2">
            <CardTitle className="text-base leading-snug">{article.title}</CardTitle>
            <StatusBadge status={article.status} />
          </div>
          {article.category && (
            <CardDescription className="flex items-center gap-1">
              <FolderTree className="h-3 w-3" /> {article.category}
            </CardDescription>
          )}
        </CardHeader>
        <CardContent className="space-y-3">
          {article.excerpt && (
            <p className="line-clamp-2 text-sm text-muted-foreground">{article.excerpt}</p>
          )}
          {article.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {article.tags.slice(0, 5).map((t) => (
                <Badge key={t} variant="outline" className="text-xs">
                  {t}
                </Badge>
              ))}
            </div>
          )}
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Eye className="h-3 w-3" /> {article.view_count}
            </span>
            <span className="flex items-center gap-1">
              <ThumbsUp className="h-3 w-3" /> {article.helpful_count}
            </span>
            <span className="ml-auto">{fmtDate(article.updated_at)}</span>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

export default function KnowledgeBasePage() {
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [searchInput, setSearchInput] = useState("");
  const [query, setQuery] = useState("");
  const [categoryId, setCategoryId] = useState<string>("");

  const categoriesQuery = useQuery({
    queryKey: ["kb", "categories"],
    queryFn: listCategories,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const tagsQuery = useQuery({
    queryKey: ["kb", "tags"],
    queryFn: () => listPopularTags(20),
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const articlesQuery = useQuery({
    queryKey: ["kb", "articles", { categoryId, query }],
    queryFn: () => {
      if (query.trim()) {
        return searchArticles(query.trim(), { limit: 50 }).then((r) => ({
          items: r.items,
          cursor: r.cursor,
          total: r.items.length,
        }));
      }
      return listArticles({
        status: "published",
        category_id: categoryId || undefined,
        limit: 50,
      });
    },
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const notEnabled = useMemo(
    () =>
      isNotEnabledError(articlesQuery.error) ||
      isNotEnabledError(categoriesQuery.error),
    [articlesQuery.error, categoriesQuery.error],
  );

  function runSearch() {
    setQuery(searchInput);
  }

  if (notEnabled) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Knowledge Base"
          description="Browse help articles, guides, and FAQs."
        />
        <KbNotEnabledCard />
      </div>
    );
  }

  const articles = articlesQuery.data?.items ?? [];
  const categories = categoriesQuery.data?.categories ?? [];
  const tags = tagsQuery.data?.tags ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Knowledge Base"
        description="Browse help articles, guides, and FAQs."
        actions={
          <div className="flex items-center gap-2">
            <Button asChild variant="outline">
              <Link to="/crm/knowledge-base/portal">
                <BookOpen className="mr-2 h-4 w-4" /> Public portal
              </Link>
            </Button>
            {isAdmin && (
              <>
                <Button asChild variant="outline">
                  <Link to="/crm/knowledge-base/manage">Manage</Link>
                </Button>
                <Button onClick={() => navigate("/crm/knowledge-base/articles/new")}>
                  <Plus className="mr-2 h-4 w-4" /> New article
                </Button>
              </>
            )}
          </div>
        }
      />

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") runSearch();
            }}
            placeholder="Search articles…"
            className="pl-8"
          />
        </div>
        <Button onClick={runSearch}>Search</Button>
        {query && (
          <Button
            variant="ghost"
            onClick={() => {
              setQuery("");
              setSearchInput("");
            }}
          >
            Clear
          </Button>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
        <aside className="space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                <FolderTree className="h-4 w-4" /> Categories
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <button
                onClick={() => setCategoryId("")}
                className={`block w-full rounded px-2 py-1 text-left text-sm hover:bg-muted ${
                  categoryId === "" ? "bg-muted font-medium" : ""
                }`}
              >
                All articles
              </button>
              {categoriesQuery.isLoading && (
                <Skeleton className="h-6 w-full" />
              )}
              {categories.map((c) => (
                <button
                  key={c.category_id}
                  onClick={() => {
                    setCategoryId(c.category_id);
                    setQuery("");
                    setSearchInput("");
                  }}
                  className={`block w-full rounded px-2 py-1 text-left text-sm hover:bg-muted ${
                    categoryId === c.category_id ? "bg-muted font-medium" : ""
                  }`}
                >
                  {c.name}
                </button>
              ))}
              {!categoriesQuery.isLoading && categories.length === 0 && (
                <p className="px-2 text-xs text-muted-foreground">No categories yet.</p>
              )}
            </CardContent>
          </Card>

          {tags.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Tag className="h-4 w-4" /> Popular tags
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-1">
                {tags.map((t) => (
                  <Link
                    key={t.tag}
                    to={`/crm/knowledge-base/tags/${encodeURIComponent(t.tag)}`}
                  >
                    <Badge variant="outline" className="cursor-pointer text-xs">
                      {t.tag} ({t.article_count})
                    </Badge>
                  </Link>
                ))}
              </CardContent>
            </Card>
          )}
        </aside>

        <section>
          {articlesQuery.isLoading ? (
            <div className="grid gap-4 sm:grid-cols-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-40 w-full" />
              ))}
            </div>
          ) : articles.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
                <BookOpen className="h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  {query
                    ? `No articles match "${query}".`
                    : "No published articles yet."}
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              {articles.map((a) => (
                <ArticleCard key={a.article_id} article={a} />
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
