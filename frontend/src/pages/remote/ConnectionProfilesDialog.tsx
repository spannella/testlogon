import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { connectionProfilesApi } from "@/api/endpoints/connectionProfiles";
import type {
  ConnectionProfile,
  CreateConnectionProfileInput,
  ConnectionProtocol,
  ConnectionAuthMethod,
  TerminalColorScheme,
} from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/components/ui/use-toast";

interface ConnectionProfilesDialogProps {
  open: boolean;
  onClose: () => void;
  profile?: ConnectionProfile | null;
}

const COLOR_SCHEMES: TerminalColorScheme[] = [
  "dark",
  "light",
  "monokai",
  "solarized",
  "dracula",
];

export default function ConnectionProfilesDialog({
  open,
  onClose,
  profile,
}: ConnectionProfilesDialogProps) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const isEdit = !!profile;

  const [label, setLabel] = useState("");
  const [protocol, setProtocol] = useState<ConnectionProtocol>("ssh");
  const [hostname, setHostname] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("");
  const [authMethod, setAuthMethod] = useState<ConnectionAuthMethod>("key_ref");
  const [sshKeyId, setSshKeyId] = useState("");
  const [bastionPathId, setBastionPathId] = useState("");
  const [cols, setCols] = useState(80);
  const [rows, setRows] = useState(24);
  const [fontSize, setFontSize] = useState(14);
  const [colorScheme, setColorScheme] = useState<TerminalColorScheme>("dark");
  const [isFavorite, setIsFavorite] = useState(false);
  const [autoConnect, setAutoConnect] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLabel(profile?.label ?? "");
    setProtocol(profile?.protocol ?? "ssh");
    setHostname(profile?.hostname ?? "");
    setPort(profile?.port ?? 22);
    setUsername(profile?.username ?? "");
    setAuthMethod(profile?.auth_method ?? "key_ref");
    setSshKeyId(profile?.ssh_key_id ?? "");
    setBastionPathId(profile?.bastion_path_id ?? "");
    setCols(profile?.terminal_cols ?? 80);
    setRows(profile?.terminal_rows ?? 24);
    setFontSize(profile?.terminal_font_size ?? 14);
    setColorScheme(profile?.terminal_color_scheme ?? "dark");
    setIsFavorite(profile?.is_favorite ?? false);
    setAutoConnect(profile?.auto_connect ?? false);
  }, [open, profile]);

  const saveMut = useMutation({
    mutationFn: () => {
      const body: CreateConnectionProfileInput = {
        label,
        protocol,
        hostname,
        port,
        username,
        auth_method: authMethod,
        ssh_key_id: sshKeyId,
        bastion_path_id: bastionPathId,
        terminal_cols: cols,
        terminal_rows: rows,
        terminal_font_size: fontSize,
        terminal_color_scheme: colorScheme,
        is_favorite: isFavorite,
        auto_connect: autoConnect,
      };
      if (isEdit && profile) {
        return connectionProfilesApi.update(profile.profile_id, body);
      }
      return connectionProfilesApi.create(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["connection-profiles"] });
      toast({ title: isEdit ? "Profile updated" : "Profile created" });
      onClose();
    },
    onError: () => {
      toast({ title: "Failed to save profile", variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? "Edit Connection Profile" : "New Connection Profile"}
          </DialogTitle>
          <DialogDescription>
            Save a named connection for one-click quick connect.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="cp-label">Label</Label>
            <Input
              id="cp-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Dev Server"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Protocol</Label>
              <Select
                value={protocol}
                onValueChange={(v) => setProtocol(v as ConnectionProtocol)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ssh">SSH</SelectItem>
                  <SelectItem value="vnc">VNC</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cp-port">Port</Label>
              <Input
                id="cp-port"
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="cp-host">Hostname / IP</Label>
            <Input
              id="cp-host"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="10.0.0.1"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="cp-user">Username</Label>
            <Input
              id="cp-user"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="ubuntu"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Auth method</Label>
              <Select
                value={authMethod}
                onValueChange={(v) => setAuthMethod(v as ConnectionAuthMethod)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="key_ref">Stored key</SelectItem>
                  <SelectItem value="key">Key</SelectItem>
                  <SelectItem value="password">Password</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cp-key">SSH key ID</Label>
              <Input
                id="cp-key"
                value={sshKeyId}
                onChange={(e) => setSshKeyId(e.target.value)}
                placeholder="(optional)"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="cp-bastion">Bastion path ID</Label>
            <Input
              id="cp-bastion"
              value={bastionPathId}
              onChange={(e) => setBastionPathId(e.target.value)}
              placeholder="(optional jump-host chain)"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="cp-cols">Columns</Label>
              <Input
                id="cp-cols"
                type="number"
                value={cols}
                onChange={(e) => setCols(Number(e.target.value))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cp-rows">Rows</Label>
              <Input
                id="cp-rows"
                type="number"
                value={rows}
                onChange={(e) => setRows(Number(e.target.value))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cp-font">Font size</Label>
              <Input
                id="cp-font"
                type="number"
                value={fontSize}
                onChange={(e) => setFontSize(Number(e.target.value))}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label>Color scheme</Label>
            <Select
              value={colorScheme}
              onValueChange={(v) => setColorScheme(v as TerminalColorScheme)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {COLOR_SCHEMES.map((c) => (
                  <SelectItem key={c} value={c}>
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="cp-fav">Pin as favorite</Label>
            <Switch
              id="cp-fav"
              checked={isFavorite}
              onCheckedChange={setIsFavorite}
            />
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="cp-auto">Auto-connect</Label>
            <Switch
              id="cp-auto"
              checked={autoConnect}
              onCheckedChange={setAutoConnect}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => saveMut.mutate()}
            disabled={!label.trim() || saveMut.isPending}
          >
            {isEdit ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
