import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Link2, Loader2, Unlink2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  beginJiraConnect,
  completeJiraCallback,
  disconnectJira,
  getJiraPreferences,
  getJiraStatus,
  listJiraProjects,
  putJiraPreferences,
  type JiraConnection,
} from "@/api/endpoints/jira";

function parseQueryParams() {
  const params = new URLSearchParams(window.location.search);
  return {
    code: params.get("code"),
    state: params.get("state"),
  };
}

export function JiraIntegrationSettings() {
  const queryClient = useQueryClient();
  const [workspaceId, setWorkspaceId] = React.useState("");
  const [selectedCloudId, setSelectedCloudId] = React.useState("");
  const [selectedProjects, setSelectedProjects] = React.useState<string[]>([]);
  const [validationError, setValidationError] = React.useState<string | null>(null);

  const statusQuery = useQuery({
    queryKey: ["jira-status", workspaceId],
    queryFn: () => getJiraStatus(workspaceId),
    enabled: workspaceId.trim().length > 0,
  });

  const activeConnection: JiraConnection | null = React.useMemo(() => {
    if (!statusQuery.data?.items?.length) return null;
    return statusQuery.data.items.find((item) => item.status === "active") ?? statusQuery.data.items[0] ?? null;
  }, [statusQuery.data]);

  React.useEffect(() => {
    if (!activeConnection?.cloud_id) return;
    setSelectedCloudId(activeConnection.cloud_id);
  }, [activeConnection?.cloud_id]);

  const callbackMutation = useMutation({
    mutationFn: ({ code, state }: { code: string; state: string }) => completeJiraCallback(code, state),
    onSuccess: (data) => {
      if (data.status === "connected") {
        toast.success("Jira connected");
      } else {
        toast.error(`Jira callback failed: ${data.error_code ?? "unknown error"}`);
      }
      queryClient.invalidateQueries({ queryKey: ["jira-status", workspaceId] });
      const params = new URLSearchParams(window.location.search);
      params.delete("code");
      params.delete("state");
      const next = params.toString();
      window.history.replaceState({}, "", `${window.location.pathname}${next ? `?${next}` : ""}`);
    },
    onError: () => {
      toast.error("Unable to complete Jira callback");
    },
  });

  React.useEffect(() => {
    const { code, state } = parseQueryParams();
    if (!code || !state || callbackMutation.isPending || callbackMutation.isSuccess) return;
    callbackMutation.mutate({ code, state });
  }, [callbackMutation]);

  const connectMutation = useMutation({
    mutationFn: () => beginJiraConnect(workspaceId, `${window.location.origin}/settings`),
    onSuccess: (data) => {
      window.location.href = data.connect_url;
    },
    onError: () => {
      toast.error("Unable to start Jira OAuth connection");
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: (connectionId: string) => disconnectJira(workspaceId, connectionId),
    onSuccess: () => {
      toast.success("Jira disconnected");
      queryClient.invalidateQueries({ queryKey: ["jira-status", workspaceId] });
    },
    onError: () => {
      toast.error("Unable to disconnect Jira");
    },
  });

  const projectsQuery = useQuery({
    queryKey: ["jira-projects", workspaceId, selectedCloudId],
    queryFn: () => listJiraProjects(workspaceId, selectedCloudId),
    enabled: workspaceId.trim().length > 0 && selectedCloudId.trim().length > 0,
  });

  const prefsQuery = useQuery({
    queryKey: ["jira-prefs", workspaceId, selectedCloudId],
    queryFn: () => getJiraPreferences(workspaceId, selectedCloudId),
    enabled: workspaceId.trim().length > 0 && selectedCloudId.trim().length > 0,
  });

  React.useEffect(() => {
    setSelectedProjects(prefsQuery.data?.project_keys ?? []);
  }, [prefsQuery.data?.project_keys]);

  const savePrefsMutation = useMutation({
    mutationFn: () => putJiraPreferences(workspaceId, selectedCloudId, selectedProjects),
    onSuccess: () => {
      toast.success("Jira project preferences saved");
      queryClient.invalidateQueries({ queryKey: ["jira-prefs", workspaceId, selectedCloudId] });
    },
    onError: () => {
      toast.error("Unable to save Jira project preferences");
    },
  });

  function validateWorkspace(): boolean {
    const value = workspaceId.trim();
    if (!value) {
      setValidationError("Workspace ID is required.");
      return false;
    }
    setValidationError(null);
    return true;
  }

  function onConnectClick() {
    if (!validateWorkspace()) return;
    connectMutation.mutate();
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Jira Integration</CardTitle>
          <CardDescription>Connect Jira, view connection status, and configure project preferences.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="jira-workspace-id">Workspace ID</Label>
            <Input
              id="jira-workspace-id"
              placeholder="ws_123"
              value={workspaceId}
              onChange={(e) => setWorkspaceId(e.target.value)}
            />
            {validationError && <p className="text-sm text-destructive">{validationError}</p>}
          </div>

          <div className="flex flex-wrap gap-2">
            <Button onClick={onConnectClick} disabled={connectMutation.isPending}>
              {connectMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Link2 className="mr-2 h-4 w-4" />}
              Connect Jira
            </Button>
            {activeConnection && (
              <Button
                variant="outline"
                onClick={() => disconnectMutation.mutate(activeConnection.connection_id)}
                disabled={disconnectMutation.isPending}
              >
                {disconnectMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlink2 className="mr-2 h-4 w-4" />}
                Disconnect
              </Button>
            )}
          </div>

          {statusQuery.isError && <p className="text-sm text-destructive">Failed to load Jira connection status.</p>}
          {statusQuery.isFetching && <p className="text-sm text-muted-foreground">Loading connection state…</p>}
          {activeConnection ? (
            <div className="rounded-md border bg-muted/20 p-3 text-sm">
              <p className="mb-1 flex items-center gap-2 font-medium">
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                Connected to {activeConnection.site_url}
              </p>
              <p className="text-muted-foreground">Cloud ID: {activeConnection.cloud_id}</p>
              <p className="text-muted-foreground">Status: {activeConnection.status}</p>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No active Jira connection for this workspace.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Project Preferences</CardTitle>
          <CardDescription>Choose which Jira projects to include in sync/mirror workflows.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {(!workspaceId.trim() || !selectedCloudId.trim()) && (
            <p className="text-sm text-muted-foreground">Connect Jira and provide workspace ID to edit project preferences.</p>
          )}
          {projectsQuery.isError && <p className="text-sm text-destructive">Unable to load Jira projects.</p>}
          {prefsQuery.isError && <p className="text-sm text-destructive">Unable to load saved preferences.</p>}
          {projectsQuery.data?.items?.length ? (
            <div className="max-h-64 space-y-2 overflow-auto rounded-md border p-3">
              {projectsQuery.data.items.map((project) => {
                const checked = selectedProjects.includes(project.project_key);
                return (
                  <label key={project.project_id} className="flex cursor-pointer items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) => {
                        setSelectedProjects((prev) => {
                          if (e.target.checked) return [...prev, project.project_key];
                          return prev.filter((x) => x !== project.project_key);
                        });
                      }}
                    />
                    <span className="font-medium">{project.project_key}</span>
                    <span className="text-muted-foreground">{project.name}</span>
                  </label>
                );
              })}
            </div>
          ) : null}
          <Button
            onClick={() => savePrefsMutation.mutate()}
            disabled={!workspaceId.trim() || !selectedCloudId.trim() || savePrefsMutation.isPending}
          >
            {savePrefsMutation.isPending ? "Saving..." : "Save Project Preferences"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
