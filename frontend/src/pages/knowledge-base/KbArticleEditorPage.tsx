import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Save, Send, Trash2, Undo2 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  createArticle,
  deleteArticle,
  expireArticle,
  getArticle,
  listCategories,
  publishArticle,
  unpublishArticle,
  updateArticle,
} from "@/api/endpoints/knowledgeBase";
import {
  errMessage,
  isNotEnabledError,
  KbNotEnabledCard,
  StatusBadge,
} from "./kbShared";

const NO_CATEGORY = "__none__";

export default function KbArticleEditorPage() {
  const { articleId } = useParams<{ articleId: string }>();
  const isEdit = !!articleId && articleId !== "new";
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [title, setTitle] = useState("");
  const [excerpt, setExcerpt] = useState("");
  const [bodyHtml, setBodyHtml] = useState("");
  const [categoryId, setCategoryId] = useState<string>(NO_CATEGORY);
  const [tagsInput, setTagsInput] = useState("");

  const categoriesQuery = useQuery({
    queryKey: ["kb", "categories"],
    queryFn: listCategories,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  const articleQuery = useQuery({
    queryKey: ["kb", "article", articleId],
    queryFn: () => getArticle(articleId!),
    enabled: isEdit,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  useEffect(() => {
    const a = articleQuery.data;
    if (a) {
      setTitle(a.title);
      setExcerpt(a.excerpt);
      setBodyHtml(a.body_html);
      setCategoryId(a.category_id ?? NO_CATEGORY);
      setTagsInput(a.tags.join(", "));
    }
  }, [articleQuery.data]);

  const parseTags = () =>
    tagsInput
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

  const payload = () => ({
    title: title.trim(),
    excerpt: excerpt.trim(),
    body_html: bodyHtml,
    category_id: categoryId === NO_CATEGORY ? null : categoryId,
    tags: parseTags(),
  });

  const createMut = useMutation({
    mutationFn: () => createArticle(payload()),
    onSuccess: (res) => {
      toast.success("Draft created");
      void queryClient.invalidateQueries({ queryKey: ["kb", "articles"] });
      navigate(`/crm/knowledge-base/articles/${encodeURIComponent(res.article_id)}/edit`);
    },
    onError: (err) => toast.error(errMessage(err, "Unable to create article")),
  });

  const updateMut = useMutation({
    mutationFn: () => updateArticle(articleId!, payload()),
    onSuccess: () => {
      toast.success("Changes saved");
      void queryClient.invalidateQueries({ queryKey: ["kb", "article", articleId] });
      void queryClient.invalidateQueries({ queryKey: ["kb", "articles"] });
    },
    onError: (err) => toast.error(errMessage(err, "Unable to save changes")),
  });

  const publishMut = useMutation({
    mutationFn: () => publishArticle(articleId!),
    onSuccess: () => {
      toast.success("Article published");
      void queryClient.invalidateQueries({ queryKey: ["kb", "article", articleId] });
      void queryClient.invalidateQueries({ queryKey: ["kb", "articles"] });
    },
    onError: (err) => toast.error(errMessage(err, "Unable to publish")),
  });

  const unpublishMut = useMutation({
    mutationFn: () => unpublishArticle(articleId!),
    onSuccess: () => {
      toast.success("Reverted to draft");
      void queryClient.invalidateQueries({ queryKey: ["kb", "article", articleId] });
      void queryClient.invalidateQueries({ queryKey: ["kb", "articles"] });
    },
    onError: (err) => toast.error(errMessage(err, "Unable to unpublish")),
  });

  const expireMut = useMutation({
    mutationFn: () => expireArticle(articleId!, "Manually expired"),
    onSuccess: () => {
      toast.success("Article expired");
      void queryClient.invalidateQueries({ queryKey: ["kb", "article", articleId] });
      void queryClient.invalidateQueries({ queryKey: ["kb", "articles"] });
    },
    onError: (err) => toast.error(errMessage(err, "Unable to expire")),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteArticle(articleId!),
    onSuccess: () => {
      toast.success("Article deleted");
      void queryClient.invalidateQueries({ queryKey: ["kb", "articles"] });
      navigate("/crm/knowledge-base/manage");
    },
    onError: (err) => toast.error(errMessage(err, "Unable to delete")),
  });

  if (isNotEnabledError(categoriesQuery.error) || isNotEnabledError(articleQuery.error)) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" asChild>
          <Link to="/crm/knowledge-base/manage">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Link>
        </Button>
        <KbNotEnabledCard />
      </div>
    );
  }

  if (isEdit && articleQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-1/2" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const article = articleQuery.data;
  const status = article?.status;
  const categories = categoriesQuery.data?.categories ?? [];
  const canSave = title.trim().length > 0;

  return (
    <div className="space-y-6">
      <Button variant="ghost" asChild className="w-fit">
        <Link to="/crm/knowledge-base/manage">
          <ArrowLeft className="mr-2 h-4 w-4" /> Back to manage
        </Link>
      </Button>

      <PageHeader
        title={isEdit ? "Edit article" : "New article"}
        description={
          isEdit
            ? "Update content, then publish or revert to draft."
            : "Create a draft article. Publish it when ready."
        }
        actions={status ? <StatusBadge status={status} /> : undefined}
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
        <Card>
          <CardContent className="space-y-4 py-6">
            <div className="space-y-1.5">
              <Label htmlFor="kb-title">Title</Label>
              <Input
                id="kb-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="How to reset your password"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-excerpt">Excerpt</Label>
              <Textarea
                id="kb-excerpt"
                value={excerpt}
                onChange={(e) => setExcerpt(e.target.value)}
                placeholder="Short summary shown in lists and search results"
                rows={2}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-body">Body (HTML)</Label>
              <Textarea
                id="kb-body"
                value={bodyHtml}
                onChange={(e) => setBodyHtml(e.target.value)}
                placeholder="<p>Article content…</p>"
                rows={18}
                className="font-mono text-sm"
              />
            </div>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Metadata</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label>Category</Label>
                <Select value={categoryId} onValueChange={setCategoryId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Uncategorized" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NO_CATEGORY}>Uncategorized</SelectItem>
                    {categories.map((c) => (
                      <SelectItem key={c.category_id} value={c.category_id}>
                        {c.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="kb-tags">Tags (comma-separated)</Label>
                <Input
                  id="kb-tags"
                  value={tagsInput}
                  onChange={(e) => setTagsInput(e.target.value)}
                  placeholder="billing, account, faq"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {isEdit ? (
                <>
                  <Button
                    className="w-full"
                    disabled={!canSave || updateMut.isPending}
                    onClick={() => updateMut.mutate()}
                  >
                    <Save className="mr-2 h-4 w-4" /> Save changes
                  </Button>
                  {status === "draft" && (
                    <Button
                      className="w-full"
                      variant="outline"
                      disabled={publishMut.isPending}
                      onClick={() => publishMut.mutate()}
                    >
                      <Send className="mr-2 h-4 w-4" /> Publish
                    </Button>
                  )}
                  {status === "published" && (
                    <>
                      <Button
                        className="w-full"
                        variant="outline"
                        disabled={unpublishMut.isPending}
                        onClick={() => unpublishMut.mutate()}
                      >
                        <Undo2 className="mr-2 h-4 w-4" /> Unpublish to draft
                      </Button>
                      <Button
                        className="w-full"
                        variant="outline"
                        disabled={expireMut.isPending}
                        onClick={() => expireMut.mutate()}
                      >
                        Expire
                      </Button>
                    </>
                  )}
                  {status === "expired" && (
                    <Button
                      className="w-full"
                      variant="outline"
                      disabled={publishMut.isPending}
                      onClick={() => publishMut.mutate()}
                    >
                      <Send className="mr-2 h-4 w-4" /> Re-publish
                    </Button>
                  )}
                  <Button
                    className="w-full"
                    variant="destructive"
                    disabled={deleteMut.isPending}
                    onClick={() => {
                      if (window.confirm("Delete this article permanently?")) {
                        deleteMut.mutate();
                      }
                    }}
                  >
                    <Trash2 className="mr-2 h-4 w-4" /> Delete
                  </Button>
                </>
              ) : (
                <Button
                  className="w-full"
                  disabled={!canSave || createMut.isPending}
                  onClick={() => createMut.mutate()}
                >
                  <Save className="mr-2 h-4 w-4" /> Create draft
                </Button>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
