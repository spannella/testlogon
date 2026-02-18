import * as React from "react";
import { ShieldCheck, Trash2, KeyRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  canRememberPasswords,
  clearAllRememberedPasswords,
  clearRememberedPassword,
  listRememberedPasswords,
  purgeExpiredRememberedPasswords,
  type RememberedPasswordInfo,
} from "@/lib/filePasswordStore";

function fmt(value?: string): string {
  if (!value) return "—";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  return new Date(ts).toLocaleString();
}

export function RememberedFilePasswords() {
  const [loading, setLoading] = React.useState(true);
  const [items, setItems] = React.useState<RememberedPasswordInfo[]>([]);
  const [busyId, setBusyId] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    if (!canRememberPasswords()) {
      setItems([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      await purgeExpiredRememberedPasswords();
      const rows = await listRememberedPasswords();
      setItems(rows);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const forgetOne = async (item: RememberedPasswordInfo) => {
    setBusyId(item.fileId);
    try {
      await clearRememberedPassword(item.fileId);
      toast.success(`Forgot remembered password for ${item.displayName || item.path || "file"}`);
      await load();
    } catch {
      toast.error("Failed to forget remembered password");
    } finally {
      setBusyId(null);
    }
  };

  const forgetAll = async () => {
    setBusyId("*");
    try {
      const removed = await clearAllRememberedPasswords();
      toast.success(removed > 0 ? `Cleared ${removed} remembered password(s)` : "No remembered passwords stored");
      await load();
    } catch {
      toast.error("Failed to clear remembered passwords");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">Manage remembered file passwords</CardTitle>
          </div>
          <Button variant="outline" size="sm" onClick={forgetAll} disabled={busyId === "*" || items.length === 0}>
            <Trash2 className="mr-1 h-3.5 w-3.5" /> Clear all
          </Button>
        </div>
        <CardDescription>
          Passwords are optional, encrypted in local browser storage, and automatically expire after 90 days.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <p className="text-sm text-muted-foreground">Loading remembered passwords…</p>
        ) : items.length === 0 ? (
          <EmptyState
            icon={<KeyRound className="h-8 w-8" />}
            title="No remembered file passwords"
            description="You can opt in while decrypting encrypted files."
          />
        ) : (
          <ul className="divide-y">
            {items.map((item) => (
              <li key={item.fileId} className="flex items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{item.displayName || item.path || item.fileId}</p>
                  <p className="truncate text-xs text-muted-foreground">{item.path || item.fileId}</p>
                  <p className="text-xs text-muted-foreground">
                    Last used {fmt(item.updatedAt || item.createdAt)} • Expires {fmt(item.expiresAt)}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => forgetOne(item)}
                  disabled={busyId === item.fileId || busyId === "*"}
                >
                  Forget
                </Button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
