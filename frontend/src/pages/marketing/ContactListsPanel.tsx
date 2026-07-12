import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Users, Plus, Trash2, UserPlus, Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

import {
  listContactLists,
  createContactList,
  deleteContactList,
  listContactListMembers,
  addContactListMember,
  removeContactListMember,
  seedListFromContacts,
  type ContactList,
} from "@/api/endpoints/marketing";
import { EmptyState, NotEnabledCard, errMsg, fmtTs, isNotEnabledError } from "./shared";

export function ContactListsPanel() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [newParty, setNewParty] = useState("");

  const listsQ = useQuery({
    queryKey: ["mkt", "lists"],
    queryFn: () => listContactLists(),
    retry: false,
  });

  const membersQ = useQuery({
    queryKey: ["mkt", "list", selectedId, "members"],
    queryFn: () => listContactListMembers(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () => createContactList({ name: name.trim(), description: desc.trim() || undefined }),
    onSuccess: (l) => {
      toast.success("List created");
      setCreateOpen(false);
      setName("");
      setDesc("");
      setSelectedId(l.list_id);
      void qc.invalidateQueries({ queryKey: ["mkt", "lists"] });
    },
    onError: (e) => toast.error(errMsg(e, "Unable to create list")),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteContactList(id),
    onSuccess: () => {
      toast.success("List deleted");
      setSelectedId(null);
      void qc.invalidateQueries({ queryKey: ["mkt", "lists"] });
    },
    onError: (e) => toast.error(errMsg(e, "Delete failed")),
  });

  const addMut = useMutation({
    mutationFn: () => addContactListMember(selectedId!, newParty.trim()),
    onSuccess: () => {
      toast.success("Member added");
      setNewParty("");
      void qc.invalidateQueries({ queryKey: ["mkt", "list", selectedId, "members"] });
      void qc.invalidateQueries({ queryKey: ["mkt", "lists"] });
    },
    onError: (e) => toast.error(errMsg(e, "Add failed")),
  });

  const removeMut = useMutation({
    mutationFn: (partyId: string) => removeContactListMember(selectedId!, partyId),
    onSuccess: () => {
      toast.success("Member removed");
      void qc.invalidateQueries({ queryKey: ["mkt", "list", selectedId, "members"] });
      void qc.invalidateQueries({ queryKey: ["mkt", "lists"] });
    },
    onError: (e) => toast.error(errMsg(e, "Remove failed")),
  });

  const seedMut = useMutation({
    mutationFn: () => seedListFromContacts(selectedId!),
    onSuccess: (r) => {
      toast.success(`Seeded: ${r.added} added, ${r.skipped} skipped`);
      void qc.invalidateQueries({ queryKey: ["mkt", "list", selectedId, "members"] });
      void qc.invalidateQueries({ queryKey: ["mkt", "lists"] });
    },
    onError: (e) => toast.error(errMsg(e, "Seed failed")),
  });

  if (isNotEnabledError(listsQ.error)) {
    return <NotEnabledCard what="Contact lists" />;
  }

  const lists = listsQ.data ?? [];
  const members = membersQ.data ?? [];

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-4 w-4" /> Contact lists
            </CardTitle>
            <CardDescription>{lists.length} list(s)</CardDescription>
          </div>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-3.5 w-3.5" /> New
          </Button>
        </CardHeader>
        <CardContent>
          {listsQ.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : lists.length === 0 ? (
            <EmptyState title="No contact lists" hint="Create a list to group recipients." />
          ) : (
            <div className="space-y-1">
              {lists.map((l: ContactList) => (
                <button
                  key={l.list_id}
                  data-testid="list-row"
                  className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm ${
                    selectedId === l.list_id ? "bg-muted" : ""
                  }`}
                  onClick={() => setSelectedId(l.list_id)}
                >
                  <span className="font-medium">{l.name}</span>
                  <Badge variant="secondary">{l.member_count}</Badge>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Members</CardTitle>
            <CardDescription>
              {selectedId ? `${members.length} member(s)` : "Select a list"}
            </CardDescription>
          </div>
          {selectedId && (
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={seedMut.isPending}
                onClick={() => seedMut.mutate()}
              >
                <Download className="mr-1 h-3.5 w-3.5" /> Seed from contacts
              </Button>
              <Button
                variant="destructive"
                size="sm"
                disabled={deleteMut.isPending}
                onClick={() => deleteMut.mutate(selectedId)}
              >
                <Trash2 className="mr-1 h-3.5 w-3.5" /> Delete list
              </Button>
            </div>
          )}
        </CardHeader>
        <CardContent className="space-y-3">
          {!selectedId ? (
            <EmptyState title="No list selected" />
          ) : (
            <>
              <div className="flex gap-2">
                <Input
                  placeholder="party_id to add"
                  value={newParty}
                  onChange={(e) => setNewParty(e.target.value)}
                />
                <Button
                  disabled={!newParty.trim() || addMut.isPending}
                  onClick={() => addMut.mutate()}
                >
                  <UserPlus className="mr-1 h-3.5 w-3.5" /> Add
                </Button>
              </div>

              {membersQ.isLoading ? (
                <Skeleton className="h-24 w-full" />
              ) : members.length === 0 ? (
                <EmptyState title="No members" hint="Add a party id or seed from contacts." />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Party</TableHead>
                      <TableHead>Joined</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {members.map((m) => (
                      <TableRow key={m.party_id}>
                        <TableCell className="font-mono text-xs">
                          {m.display_name || m.party_id}
                        </TableCell>
                        <TableCell>{fmtTs(m.joined_at)}</TableCell>
                        <TableCell>
                          {m.suppressed ? (
                            <Badge variant="destructive">suppressed</Badge>
                          ) : (
                            <Badge variant="secondary">active</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeMut.mutate(m.party_id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New contact list</DialogTitle>
            <DialogDescription>Group recipients for campaign sends.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="list-name">Name</Label>
              <Input id="list-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="list-desc">Description</Label>
              <Input id="list-desc" value={desc} onChange={(e) => setDesc(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button disabled={!name.trim() || createMut.isPending} onClick={() => createMut.mutate()}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
