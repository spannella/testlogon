import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText } from "lucide-react";
import {
  approveContent,
  getContent,
  scheduleContent,
  updateContent,
} from "@/api/endpoints/marketingAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

export default function MarketingContentEditorPage() {
  const { contentId = "" } = useParams();
  const qc = useQueryClient();
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [summary, setSummary] = useState("");
  const [tags, setTags] = useState("");
  const [metaTitle, setMetaTitle] = useState("");
  const [metaDescription, setMetaDescription] = useState("");
  const [scheduleAt, setScheduleAt] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["marketing-content-detail", contentId],
    queryFn: () => getContent(contentId),
    enabled: !!contentId,
  });

  useEffect(() => {
    if (data) {
      setTitle(data.title);
      setBody(data.body);
      setSummary(data.summary ?? "");
      setTags((data.tags ?? []).join(", "));
      setMetaTitle((data.seo_meta?.title as string) ?? "");
      setMetaDescription((data.seo_meta?.description as string) ?? "");
    }
  }, [data]);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["marketing-content-detail", contentId] });
    qc.invalidateQueries({ queryKey: ["marketing-content"] });
  };

  const saveMut = useMutation({
    mutationFn: () =>
      updateContent(contentId, {
        title,
        body,
        summary: summary || undefined,
        tags: tags ? tags.split(",").map((t) => t.trim()).filter(Boolean) : undefined,
        seo_meta:
          metaTitle || metaDescription
            ? { title: metaTitle, description: metaDescription }
            : undefined,
      }),
    onSuccess: invalidate,
  });

  const approveMut = useMutation({
    mutationFn: () => approveContent(contentId),
    onSuccess: invalidate,
  });

  const scheduleMut = useMutation({
    mutationFn: () => scheduleContent(contentId, Math.floor(new Date(scheduleAt).getTime() / 1000)),
    onSuccess: invalidate,
  });

  if (isLoading) return <p className="p-4">Loading…</p>;

  return (
    <div data-testid="content-editor-page" className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Content Editor</h1>
          {data && <Badge variant="secondary">{data.status}</Badge>}
        </div>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/marketing">Back</Link>
          </Button>
          <Button size="sm" onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
            Save
          </Button>
          {data && (data.status === "draft" || data.status === "review") && (
            <Button size="sm" onClick={() => approveMut.mutate()}>
              Approve
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="space-y-3 md:col-span-2">
          <div>
            <Label>Title</Label>
            <Input
              data-testid="editor-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          <div>
            <Label>Body (markdown)</Label>
            <Textarea
              data-testid="editor-body"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={16}
              className="font-mono"
            />
          </div>
          <div>
            <Label>Summary</Label>
            <Textarea
              data-testid="editor-summary"
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              rows={2}
            />
          </div>
        </div>

        <div className="space-y-4" data-testid="editor-side-panel">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">SEO Meta</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div>
                <Label>Meta Title</Label>
                <Input value={metaTitle} onChange={(e) => setMetaTitle(e.target.value)} />
              </div>
              <div>
                <Label>Meta Description</Label>
                <Textarea
                  value={metaDescription}
                  onChange={(e) => setMetaDescription(e.target.value)}
                  rows={3}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Tags</CardTitle>
            </CardHeader>
            <CardContent>
              <Input
                data-testid="editor-tags"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="comma, separated, tags"
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Schedule</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                type="datetime-local"
                data-testid="editor-schedule-at"
                value={scheduleAt}
                onChange={(e) => setScheduleAt(e.target.value)}
              />
              <Button
                size="sm"
                disabled={!scheduleAt || data?.status !== "approved"}
                onClick={() => scheduleMut.mutate()}
              >
                Schedule
              </Button>
              {data?.status !== "approved" && (
                <p className="text-xs text-muted-foreground">Approve content before scheduling.</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
