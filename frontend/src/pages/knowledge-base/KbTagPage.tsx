import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Eye, ThumbsUp } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { listArticlesByTag } from "@/api/endpoints/knowledgeBase";
import { fmtDate, isNotEnabledError, KbNotEnabledCard, StatusBadge } from "./kbShared";

export default function KbTagPage() {
  const { tag = "" } = useParams<{ tag: string }>();

  const query = useQuery({
    queryKey: ["kb", "tag", tag],
    queryFn: () => listArticlesByTag(tag, { limit: 100 }),
    enabled: !!tag,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  if (isNotEnabledError(query.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title={`Articles tagged "${tag}"`} />
        <KbNotEnabledCard />
      </div>
    );
  }

  const articles = query.data?.items ?? [];

  return (
    <div className="space-y-6">
      <Button variant="ghost" asChild className="w-fit">
        <Link to="/crm/knowledge-base">
          <ArrowLeft className="mr-2 h-4 w-4" /> Back to Knowledge Base
        </Link>
      </Button>

      <PageHeader
        title={`Tagged: ${tag}`}
        description="Articles tagged with this topic."
      />

      {query.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full" />
          ))}
        </div>
      ) : articles.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No articles tagged "{tag}".
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {articles.map((a) => (
            <Link
              key={a.article_id}
              to={`/crm/knowledge-base/articles/${encodeURIComponent(a.article_id)}`}
            >
              <Card className="h-full transition-colors hover:border-primary">
                <CardHeader className="space-y-1">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base leading-snug">{a.title}</CardTitle>
                    <StatusBadge status={a.status} />
                  </div>
                </CardHeader>
                <CardContent className="space-y-2">
                  {a.excerpt && (
                    <p className="line-clamp-2 text-sm text-muted-foreground">{a.excerpt}</p>
                  )}
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Eye className="h-3 w-3" /> {a.view_count}
                    </span>
                    <span className="flex items-center gap-1">
                      <ThumbsUp className="h-3 w-3" /> {a.helpful_count}
                    </span>
                    <span className="ml-auto">{fmtDate(a.updated_at)}</span>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
