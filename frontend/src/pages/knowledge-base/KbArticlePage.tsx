import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  Eye,
  FolderTree,
  Paperclip,
  Pencil,
  ThumbsDown,
  ThumbsUp,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  getArticle,
  rateArticle,
  type KbAttachment,
} from "@/api/endpoints/knowledgeBase";
import {
  errMessage,
  fmtTs,
  isNotEnabledError,
  KbNotEnabledCard,
  StatusBadge,
} from "./kbShared";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function AttachmentRow({ att }: { att: KbAttachment }) {
  return (
    <a
      href={att.url || "#"}
      target="_blank"
      rel="noreferrer"
      className="flex items-center gap-2 rounded border px-3 py-2 text-sm hover:bg-muted"
    >
      <Paperclip className="h-4 w-4 text-muted-foreground" />
      <span className="flex-1 truncate">{att.filename}</span>
      <span className="text-xs text-muted-foreground">{fmtBytes(att.size_bytes)}</span>
    </a>
  );
}

export default function KbArticlePage() {
  const { articleId = "" } = useParams<{ articleId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [rated, setRated] = useState<null | boolean>(null);

  const articleQuery = useQuery({
    queryKey: ["kb", "article", articleId],
    queryFn: () => getArticle(articleId),
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
    enabled: !!articleId,
  });

  const rateMut = useMutation({
    mutationFn: (helpful: boolean) => rateArticle(articleId, helpful),
    onSuccess: (res, helpful) => {
      if (res.already_rated) {
        toast.info("You've already rated this article");
      } else {
        toast.success("Thanks for your feedback");
      }
      setRated(helpful);
      void queryClient.invalidateQueries({ queryKey: ["kb", "article", articleId] });
    },
    onError: (err) => toast.error(errMessage(err, "Unable to submit rating")),
  });

  if (isNotEnabledError(articleQuery.error)) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" asChild>
          <Link to="/crm/knowledge-base">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Link>
        </Button>
        <KbNotEnabledCard />
      </div>
    );
  }

  if (articleQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-2/3" />
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (articleQuery.isError || !articleQuery.data) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" asChild>
          <Link to="/crm/knowledge-base">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" asChild>
          <Link to="/crm/knowledge-base">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Knowledge Base
          </Link>
        </Button>
        {isAdmin && (
          <Button
            variant="outline"
            onClick={() =>
              navigate(`/crm/knowledge-base/articles/${encodeURIComponent(articleId)}/edit`)
            }
          >
            <Pencil className="mr-2 h-4 w-4" /> Edit
          </Button>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={article.status} />
          {article.category && (
            <Badge variant="outline" className="flex items-center gap-1">
              <FolderTree className="h-3 w-3" /> {article.category}
            </Badge>
          )}
        </div>
        <h1 className="text-3xl font-semibold tracking-tight">{article.title}</h1>
        <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1">
            <Eye className="h-4 w-4" /> {article.view_count} views
          </span>
          <span>Updated {fmtTs(article.updated_at)}</span>
          {article.published_at && <span>Published {fmtTs(article.published_at)}</span>}
        </div>
        {article.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {article.tags.map((t) => (
              <Link key={t} to={`/crm/knowledge-base/tags/${encodeURIComponent(t)}`}>
                <Badge variant="secondary" className="cursor-pointer text-xs">
                  {t}
                </Badge>
              </Link>
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
              <AttachmentRow key={a.attachment_id} att={a} />
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Was this article helpful?</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <Button
            variant={rated === true ? "default" : "outline"}
            disabled={rateMut.isPending || rated !== null}
            onClick={() => rateMut.mutate(true)}
          >
            <ThumbsUp className="mr-2 h-4 w-4" /> Yes ({article.helpful_count})
          </Button>
          <Button
            variant={rated === false ? "default" : "outline"}
            disabled={rateMut.isPending || rated !== null}
            onClick={() => rateMut.mutate(false)}
          >
            <ThumbsDown className="mr-2 h-4 w-4" /> No ({article.not_helpful_count})
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
