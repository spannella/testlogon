import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Eye, FolderTree, Paperclip } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { publicGetArticle } from "@/api/endpoints/knowledgeBase";
import {
  errMessage,
  fmtTs,
  isNotEnabledError,
  KbNotEnabledCard,
} from "./kbShared";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function KbPortalArticlePage() {
  const { articleId = "" } = useParams<{ articleId: string }>();

  const articleQuery = useQuery({
    queryKey: ["kb", "public", "article", articleId],
    queryFn: () => publicGetArticle(articleId),
    enabled: !!articleId,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  if (isNotEnabledError(articleQuery.error)) {
    return (
      <div className="mx-auto max-w-3xl space-y-6 py-4">
        <Button variant="ghost" asChild>
          <Link to="/crm/knowledge-base/portal">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Help Center
          </Link>
        </Button>
        <KbNotEnabledCard />
      </div>
    );
  }

  if (articleQuery.isLoading) {
    return (
      <div className="mx-auto max-w-3xl space-y-4 py-4">
        <Skeleton className="h-8 w-2/3" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (articleQuery.isError || !articleQuery.data) {
    return (
      <div className="mx-auto max-w-3xl space-y-6 py-4">
        <Button variant="ghost" asChild>
          <Link to="/crm/knowledge-base/portal">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Help Center
          </Link>
        </Button>
        <Card className="border-dashed">
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            {errMessage(articleQuery.error, "Article not found.")}
          </CardContent>
        </Card>
      </div>
    );
  }

  const article = articleQuery.data;

  return (
    <div className="mx-auto max-w-3xl space-y-6 py-4">
      <Button variant="ghost" asChild className="w-fit">
        <Link to="/crm/knowledge-base/portal">
          <ArrowLeft className="mr-2 h-4 w-4" /> Back to Help Center
        </Link>
      </Button>

      <div className="space-y-2">
        {article.category && (
          <Badge variant="outline" className="flex w-fit items-center gap-1">
            <FolderTree className="h-3 w-3" /> {article.category}
          </Badge>
        )}
        <h1 className="text-3xl font-semibold tracking-tight">{article.title}</h1>
        <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1">
            <Eye className="h-4 w-4" /> {article.view_count} views
          </span>
          {article.published_at && <span>Published {fmtTs(article.published_at)}</span>}
        </div>
        {article.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {article.tags.map((t) => (
              <Badge key={t} variant="secondary" className="text-xs">
                {t}
              </Badge>
            ))}
          </div>
        )}
      </div>

      <Card>
        <CardContent className="py-6">
          {article.excerpt && (
            <p className="mb-4 border-l-2 border-primary pl-4 text-muted-foreground">
              {article.excerpt}
            </p>
          )}
          <div
            className="prose prose-sm max-w-none dark:prose-invert"
            // Article body is authored HTML from the KB editor.
            dangerouslySetInnerHTML={{ __html: article.body_html }}
          />
        </CardContent>
      </Card>

      {article.attachments.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Paperclip className="h-4 w-4" /> Attachments
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {article.attachments.map((a) => (
              <a
                key={a.attachment_id}
                href={a.url || "#"}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 rounded border px-3 py-2 text-sm hover:bg-muted"
              >
                <Paperclip className="h-4 w-4 text-muted-foreground" />
                <span className="flex-1 truncate">{a.filename}</span>
                <span className="text-xs text-muted-foreground">{fmtBytes(a.size_bytes)}</span>
              </a>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
