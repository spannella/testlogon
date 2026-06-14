import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Eye, Plus } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tabs,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import { listArticles } from "@/api/endpoints/knowledgeBase";
import {
  fmtTs,
  isNotEnabledError,
  KbNotEnabledCard,
  StatusBadge,
} from "./kbShared";

type StatusTab = "all" | "draft" | "published" | "expired";

export default function KbManagePage() {
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [tab, setTab] = useState<StatusTab>("all");

  const articlesQuery = useQuery({
    queryKey: ["kb", "manage", tab],
    queryFn: () => listArticles({ status: tab, limit: 100 }),
    enabled: isAdmin,
    retry: (count, err) => !isNotEnabledError(err) && count < 2,
  });

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" asChild className="w-fit">
          <Link to="/crm/knowledge-base">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Link>
        </Button>
        <Card className="border-dashed">
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Admin access is required to manage knowledge base articles.
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isNotEnabledError(articlesQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Manage articles" />
        <KbNotEnabledCard />
      </div>
    );
  }

  const articles = articlesQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <Button variant="ghost" asChild className="w-fit">
        <Link to="/crm/knowledge-base">
          <ArrowLeft className="mr-2 h-4 w-4" /> Back to Knowledge Base
        </Link>
      </Button>

      <PageHeader
        title="Manage articles"
        description="Create, edit, publish, and expire knowledge base articles."
        actions={
          <Button onClick={() => navigate("/crm/knowledge-base/articles/new")}>
            <Plus className="mr-2 h-4 w-4" /> New article
          </Button>
        }
      />

      <Tabs value={tab} onValueChange={(v) => setTab(v as StatusTab)}>
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="draft">Drafts</TabsTrigger>
          <TabsTrigger value="published">Published</TabsTrigger>
          <TabsTrigger value="expired">Expired</TabsTrigger>
        </TabsList>
      </Tabs>

      {articlesQuery.isLoading ? (
        <Skeleton className="h-64 w-full" />
      ) : articles.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No articles in this view.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead className="text-right">Views</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {articles.map((a) => (
                  <TableRow key={a.article_id}>
                    <TableCell className="font-medium">{a.title}</TableCell>
                    <TableCell>
                      <StatusBadge status={a.status} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {a.category ?? "—"}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      <span className="inline-flex items-center gap-1">
                        <Eye className="h-3 w-3" /> {a.view_count}
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {fmtTs(a.updated_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          navigate(
                            `/crm/knowledge-base/articles/${encodeURIComponent(a.article_id)}/edit`,
                          )
                        }
                      >
                        Edit
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
