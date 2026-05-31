import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Megaphone } from "lucide-react";
import {
  approveContent,
  archiveContent,
  createContent,
  deleteContent,
  listContent,
  publishContent,
} from "@/api/endpoints/marketingAgent";
import type { MarketingContent, MarketingContentType } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

const TABS: Array<{ key: string; label: string; type?: string }> = [
  { key: "all", label: "All" },
  { key: "blog_post", label: "Blog", type: "blog_post" },
  { key: "social_twitter", label: "Social", type: "social_twitter" },
  { key: "newsletter", label: "Newsletter", type: "newsletter" },
  { key: "release_notes", label: "Release Notes", type: "release_notes" },
  { key: "changelog", label: "Changelog", type: "changelog" },
];

const STATUS_COLORS: Record<string, "secondary" | "default" | "outline" | "destructive"> = {
  draft: "secondary",
  review: "outline",
  approved: "default",
  scheduled: "outline",
  published: "default",
  archived: "destructive",
};

export default function MarketingContentDashboardPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState("all");
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [contentType, setContentType] = useState<MarketingContentType>("blog_post");

  const activeType = TABS.find((t) => t.key === tab)?.type;

  const { data, isLoading } = useQuery({
    queryKey: ["marketing-content", activeType ?? "all"],
    queryFn: () => listContent(activeType ? { type: activeType, limit: 50 } : { limit: 50 }),
    staleTime: 5_000,
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["marketing-content"] });

  const createMut = useMutation({
    mutationFn: () => createContent({ content_type: contentType, title, body }),
    onSuccess: () => {
      setShowCreate(false);
      setTitle("");
      setBody("");
      invalidate();
    },
  });

  const approveMut = useMutation({ mutationFn: approveContent, onSuccess: invalidate });
  const publishMut = useMutation({ mutationFn: publishContent, onSuccess: invalidate });
  const archiveMut = useMutation({ mutationFn: archiveContent, onSuccess: invalidate });
  const deleteMut = useMutation({ mutationFn: deleteContent, onSuccess: invalidate });

  const items = data?.items ?? [];

  return (
    <div data-testid="content-dashboard-page" className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Megaphone className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Marketing Content</h1>
        </div>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/marketing/calendar">Calendar</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/marketing/engagement">Engagement</Link>
          </Button>
          <Button
            size="sm"
            data-testid="create-content-button"
            onClick={() => setShowCreate((s) => !s)}
          >
            New Content
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2" data-testid="filter-tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`rounded-full border px-3 py-1 text-sm ${
              tab === t.key ? "bg-primary text-primary-foreground" : "bg-background"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {showCreate && (
        <Card data-testid="create-content-form">
          <CardHeader>
            <CardTitle className="text-sm">Create Content Draft</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label>Type</Label>
              <select
                data-testid="create-content-type"
                className="block w-full rounded border bg-background p-2 text-sm"
                value={contentType}
                onChange={(e) => setContentType(e.target.value as MarketingContentType)}
              >
                <option value="blog_post">Blog Post</option>
                <option value="social_twitter">Twitter/X</option>
                <option value="social_linkedin">LinkedIn</option>
                <option value="newsletter">Newsletter</option>
                <option value="release_notes">Release Notes</option>
                <option value="changelog">Changelog</option>
                <option value="landing_page">Landing Page</option>
                <option value="meta_seo">SEO Meta</option>
              </select>
            </div>
            <div>
              <Label>Title</Label>
              <Input
                data-testid="create-content-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>
            <div>
              <Label>Body</Label>
              <Textarea
                data-testid="create-content-body"
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={5}
              />
            </div>
            <Button
              data-testid="create-content-submit"
              disabled={!title || !body || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              Create
            </Button>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <p>Loading…</p>
      ) : items.length === 0 ? (
        <p data-testid="content-empty" className="text-muted-foreground">
          No marketing content yet. Create a draft to get started.
        </p>
      ) : (
        <div className="grid gap-3 md:grid-cols-2" data-testid="content-grid">
          {items.map((c) => (
            <ContentCard
              key={c.content_id}
              content={c}
              onApprove={() => approveMut.mutate(c.content_id)}
              onPublish={() => publishMut.mutate(c.content_id)}
              onArchive={() => archiveMut.mutate(c.content_id)}
              onDelete={() => deleteMut.mutate(c.content_id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ContentCard({
  content,
  onApprove,
  onPublish,
  onArchive,
  onDelete,
}: {
  content: MarketingContent;
  onApprove: () => void;
  onPublish: () => void;
  onArchive: () => void;
  onDelete: () => void;
}) {
  return (
    <Card data-testid="content-card">
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm">
            <Link
              to={`/agents/marketing/content/${content.content_id}`}
              className="hover:underline"
            >
              {content.title}
            </Link>
          </CardTitle>
          <Badge variant={STATUS_COLORS[content.status] ?? "secondary"}>
            {content.status}
          </Badge>
        </div>
        <Badge variant="outline" className="w-fit">
          {content.content_type}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        {content.summary && (
          <p className="text-muted-foreground line-clamp-2">{content.summary}</p>
        )}
        {content.feature_refs && content.feature_refs.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {content.feature_refs.map((r) => (
              <Badge key={r} variant="secondary">
                {r}
              </Badge>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-2 pt-2">
          <Button asChild size="sm" variant="outline">
            <Link to={`/agents/marketing/content/${content.content_id}`}>Edit</Link>
          </Button>
          {(content.status === "draft" || content.status === "review") && (
            <Button size="sm" onClick={onApprove}>
              Approve
            </Button>
          )}
          {(content.status === "approved" || content.status === "scheduled") && (
            <Button size="sm" onClick={onPublish}>
              Publish
            </Button>
          )}
          {content.status === "published" && (
            <Button size="sm" variant="outline" onClick={onArchive}>
              Archive
            </Button>
          )}
          {content.status === "draft" && (
            <Button size="sm" variant="destructive" onClick={onDelete}>
              Delete
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
