import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  LayoutTemplate,
  Plus,
  Rocket,
  Copy,
  MoreVertical,
  Pencil,
  Trash2,
  Laptop,
  Database,
  Globe,
  Brain,
  Container,
  Terminal,
  Server,
  Loader2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";

import {
  listTemplates,
  cloneTemplate,
  deleteTemplate,
  launchFromTemplate,
} from "@/api/endpoints/instanceTemplates";
import type { InstanceTemplate } from "@/api/types";
import { TemplateEditorDialog, TEMPLATES_QUERY_KEY } from "./TemplateEditorDialog";

const CATEGORY_TABS = [
  { value: "all", label: "All" },
  { value: "compute", label: "Compute" },
  { value: "database", label: "Database" },
  { value: "web", label: "Web" },
  { value: "ml", label: "ML" },
  { value: "custom", label: "Custom" },
];

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  laptop: Laptop,
  database: Database,
  globe: Globe,
  brain: Brain,
  container: Container,
  terminal: Terminal,
  server: Server,
};

function TemplateIcon({ icon }: { icon: string }) {
  const Cmp = ICONS[icon] || Server;
  return <Cmp className="h-5 w-5 text-primary" />;
}

function TemplateCard({
  template,
  onLaunch,
  onClone,
  onEdit,
  onDelete,
  launching,
}: {
  template: InstanceTemplate;
  onLaunch: (t: InstanceTemplate) => void;
  onClone: (t: InstanceTemplate) => void;
  onEdit: (t: InstanceTemplate) => void;
  onDelete: (t: InstanceTemplate) => void;
  launching: boolean;
}) {
  return (
    <Card data-testid="template-card" className="flex flex-col">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <TemplateIcon icon={template.icon} />
            <CardTitle className="text-base">{template.name}</CardTitle>
          </div>
          <div className="flex items-center gap-1">
            <Badge variant="outline">{template.target === "k8s" ? "K8s" : "EC2"}</Badge>
            {template.is_system ? (
              <Badge className="bg-blue-600 hover:bg-blue-600 text-white">System</Badge>
            ) : null}
            {!template.is_system && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-7 w-7">
                    <MoreVertical className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={() => onEdit(template)}>
                    <Pencil className="h-4 w-4 mr-2" /> Edit
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    className="text-destructive"
                    onClick={() => onDelete(template)}
                  >
                    <Trash2 className="h-4 w-4 mr-2" /> Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col flex-1 gap-3">
        <p className="text-sm text-muted-foreground line-clamp-3">{template.description}</p>
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge variant="secondary">{template.category}</Badge>
          {template.target === "ec2" ? (
            <Badge variant="secondary">{template.instance_type}</Badge>
          ) : (
            <Badge variant="secondary">{template.k8s_preset}</Badge>
          )}
          <span className="text-muted-foreground self-center">
            Used {template.use_count} times
          </span>
        </div>
        <div className="mt-auto flex gap-2 pt-2">
          <Button
            size="sm"
            className="flex-1"
            onClick={() => onLaunch(template)}
            disabled={launching}
          >
            {launching ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <Rocket className="h-4 w-4 mr-1" />
            )}
            Launch
          </Button>
          <Button size="sm" variant="outline" onClick={() => onClone(template)}>
            <Copy className="h-4 w-4 mr-1" /> Clone
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function TemplateBrowserPage() {
  const qc = useQueryClient();
  const [activeCategory, setActiveCategory] = useState("all");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<InstanceTemplate | undefined>(undefined);
  const [launchingId, setLaunchingId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: TEMPLATES_QUERY_KEY,
    queryFn: () => listTemplates({ include_system: true }),
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });

  const templates = data?.templates ?? [];

  const filtered = useMemo(() => {
    if (activeCategory === "all") return templates;
    return templates.filter((t) => t.category === activeCategory);
  }, [templates, activeCategory]);

  const cloneMut = useMutation({
    mutationFn: (t: InstanceTemplate) =>
      cloneTemplate(t.template_id, { new_name: `${t.name} (Clone)` }),
    onSuccess: () => {
      toast.success("Template cloned");
      qc.invalidateQueries({ queryKey: TEMPLATES_QUERY_KEY });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Clone failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (t: InstanceTemplate) => deleteTemplate(t.template_id),
    onSuccess: () => {
      toast.success("Template deleted");
      qc.invalidateQueries({ queryKey: TEMPLATES_QUERY_KEY });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Delete failed"),
  });

  const launchMut = useMutation({
    mutationFn: (t: InstanceTemplate) => launchFromTemplate(t.template_id, {}),
    onMutate: (t: InstanceTemplate) => setLaunchingId(t.template_id),
    onSuccess: (res) => {
      toast.success(`Launched ${res.target.toUpperCase()} from template`);
      qc.invalidateQueries({ queryKey: TEMPLATES_QUERY_KEY });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Launch failed"),
    onSettled: () => setLaunchingId(null),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <LayoutTemplate className="h-6 w-6" />
          <h1 className="text-2xl font-semibold">Templates</h1>
        </div>
        <Button
          onClick={() => {
            setEditing(undefined);
            setEditorOpen(true);
          }}
        >
          <Plus className="h-4 w-4 mr-1" /> Create Template
        </Button>
      </div>

      <Tabs value={activeCategory} onValueChange={setActiveCategory}>
        <TabsList>
          {CATEGORY_TABS.map((tab) => (
            <TabsTrigger key={tab.value} value={tab.value}>
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-muted-foreground">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <p className="text-muted-foreground py-12 text-center">No templates found.</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((t) => (
            <TemplateCard
              key={t.template_id}
              template={t}
              launching={launchingId === t.template_id}
              onLaunch={(tpl) => launchMut.mutate(tpl)}
              onClone={(tpl) => cloneMut.mutate(tpl)}
              onEdit={(tpl) => {
                setEditing(tpl);
                setEditorOpen(true);
              }}
              onDelete={(tpl) => deleteMut.mutate(tpl)}
            />
          ))}
        </div>
      )}

      <TemplateEditorDialog
        open={editorOpen}
        template={editing}
        onClose={() => setEditorOpen(false)}
      />
    </div>
  );
}
