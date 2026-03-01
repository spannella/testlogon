import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Star,
  MessageCircle,
  FolderOpen,
  CalendarDays,
  MoreVertical,
  UserPlus,
  User,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

import { getContacts, addContact, removeContact, updateContact } from "@/api/endpoints/contacts";
import { findOrCreateDm, sendFileShareMessage, sendCalendarShareMessage } from "@/api/endpoints/messaging";
import type { ContactEntry, FileEntry, SendCalendarShareReq } from "@/api/types";

import { UserSearch } from "@/pages/messages/UserSearch";
import { FilePickerDialog } from "@/pages/messages/FilePickerDialog";
import { CalendarPickerDialog } from "@/pages/messages/CalendarPickerDialog";

// ── Avatar ─────────────────────────────────────────────────────────────────

function ContactAvatar({ contact }: { contact: ContactEntry }) {
  if (contact.profile_photo_url) {
    return (
      <img
        src={contact.profile_photo_url}
        alt={contact.display_name}
        className="h-9 w-9 rounded-full object-cover shrink-0"
      />
    );
  }
  return (
    <div className="flex h-9 w-9 items-center justify-center rounded-full bg-muted shrink-0">
      <User className="h-4 w-4 text-muted-foreground" />
    </div>
  );
}

// ── Section header ─────────────────────────────────────────────────────────

function SectionHeader({ label }: { label: string }) {
  return (
    <h3 className="mb-1 px-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
      {label}
    </h3>
  );
}

// ── Contact row ────────────────────────────────────────────────────────────

interface ContactRowProps {
  contact: ContactEntry;
  onStar: () => void;
  onMessage: () => void;
  onFile: () => void;
  onCalendar: () => void;
  onBlock: () => void;
  onUnblock: () => void;
  onRemove: () => void;
}

function ContactRow({
  contact,
  onStar,
  onMessage,
  onFile,
  onCalendar,
  onBlock,
  onUnblock,
  onRemove,
}: ContactRowProps) {
  return (
    <div className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-accent/40 transition-colors">
      <ContactAvatar contact={contact} />

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{contact.display_name}</p>
      </div>

      {/* Quick actions */}
      <div className="flex items-center gap-1">
        {/* Star toggle */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          title={contact.is_favorite ? "Remove from favorites" : "Add to favorites"}
          onClick={onStar}
        >
          <Star
            className={cn(
              "h-4 w-4",
              contact.is_favorite ? "fill-yellow-400 text-yellow-400" : "text-muted-foreground",
            )}
          />
        </Button>

        {/* Message */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          title="Message"
          onClick={onMessage}
        >
          <MessageCircle className="h-4 w-4 text-muted-foreground" />
        </Button>

        {/* Share file */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          title="Share a file"
          onClick={onFile}
        >
          <FolderOpen className="h-4 w-4 text-muted-foreground" />
        </Button>

        {/* Share calendar */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          title="Share a calendar"
          onClick={onCalendar}
        >
          <CalendarDays className="h-4 w-4 text-muted-foreground" />
        </Button>

        {/* More actions dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8" title="More actions">
              <MoreVertical className="h-4 w-4 text-muted-foreground" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {contact.is_blocked ? (
              <DropdownMenuItem onClick={onUnblock}>Unblock</DropdownMenuItem>
            ) : (
              <DropdownMenuItem onClick={onBlock}>Block</DropdownMenuItem>
            )}
            <DropdownMenuItem
              onClick={onRemove}
              className="text-destructive focus:text-destructive"
            >
              Remove
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function ContactsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);
  const [fileShareConvoId, setFileShareConvoId] = React.useState<string | null>(null);
  const [calShareConvoId, setCalShareConvoId] = React.useState<string | null>(null);

  // ── Data ────────────────────────────────────────────────────────────────

  const { data: contacts = [] } = useQuery({
    queryKey: ["contacts"],
    queryFn: getContacts,
  });

  const invalidateContacts = () => queryClient.invalidateQueries({ queryKey: ["contacts"] });

  // ── Mutations ────────────────────────────────────────────────────────────

  const addMut = useMutation({
    mutationFn: addContact,
    onSuccess: () => {
      invalidateContacts();
      setAddOpen(false);
      toast.success("Contact added");
    },
    onError: () => toast.error("Failed to add contact"),
  });

  const removeMut = useMutation({
    mutationFn: removeContact,
    onSuccess: invalidateContacts,
    onError: () => toast.error("Failed to remove contact"),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Parameters<typeof updateContact>[1] }) =>
      updateContact(id, patch),
    onSuccess: invalidateContacts,
    onError: () => toast.error("Failed to update contact"),
  });

  // ── Action handlers ──────────────────────────────────────────────────────

  async function handleMessage(contact: ContactEntry) {
    try {
      const convo = await findOrCreateDm(contact.contact_id);
      navigate("/messages", { state: { openConversation: convo } });
    } catch {
      toast.error("Could not open conversation");
    }
  }

  async function handleFile(contact: ContactEntry) {
    try {
      const convo = await findOrCreateDm(contact.contact_id);
      setFileShareConvoId(convo.conversation_id);
    } catch {
      toast.error("Could not open conversation");
    }
  }

  async function handleCalendar(contact: ContactEntry) {
    try {
      const convo = await findOrCreateDm(contact.contact_id);
      setCalShareConvoId(convo.conversation_id);
    } catch {
      toast.error("Could not open conversation");
    }
  }

  function handleStar(contact: ContactEntry) {
    updateMut.mutate({ id: contact.contact_id, patch: { is_favorite: !contact.is_favorite } });
  }

  function handleBlock(contact: ContactEntry) {
    updateMut.mutate({ id: contact.contact_id, patch: { is_blocked: true } });
  }

  function handleUnblock(contact: ContactEntry) {
    updateMut.mutate({ id: contact.contact_id, patch: { is_blocked: false } });
  }

  function handleRemove(contact: ContactEntry) {
    removeMut.mutate(contact.contact_id);
  }

  async function handleFileSelect(entry: FileEntry, permission: "read" | "write") {
    if (!fileShareConvoId) return;
    try {
      await sendFileShareMessage(fileShareConvoId, {
        file_path: entry.path,
        permission,
      });
      toast.success("File shared!");
    } catch {
      toast.error("Failed to share file");
    } finally {
      setFileShareConvoId(null);
    }
  }

  async function handleCalendarSelect(params: SendCalendarShareReq) {
    if (!calShareConvoId) return;
    try {
      await sendCalendarShareMessage(calShareConvoId, params);
      toast.success("Calendar shared!");
    } catch {
      toast.error("Failed to share calendar");
    } finally {
      setCalShareConvoId(null);
    }
  }

  // ── Grouping ─────────────────────────────────────────────────────────────

  const favorites = contacts.filter((c) => c.is_favorite && !c.is_blocked);
  const all = contacts.filter((c) => !c.is_favorite && !c.is_blocked);
  const blocked = contacts.filter((c) => c.is_blocked);

  function renderSection(label: string, items: ContactEntry[]) {
    if (items.length === 0) return null;
    return (
      <div className="mb-4">
        <SectionHeader label={label} />
        <div className="space-y-0.5">
          {items.map((c) => (
            <ContactRow
              key={c.contact_id}
              contact={c}
              onStar={() => handleStar(c)}
              onMessage={() => handleMessage(c)}
              onFile={() => handleFile(c)}
              onCalendar={() => handleCalendar(c)}
              onBlock={() => handleBlock(c)}
              onUnblock={() => handleUnblock(c)}
              onRemove={() => handleRemove(c)}
            />
          ))}
        </div>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <h1 className="text-xl font-semibold">Contacts</h1>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <UserPlus className="mr-2 h-4 w-4" />
          Add Contact
        </Button>
      </div>

      {/* Contact list */}
      <div className="flex-1 overflow-y-auto px-4 py-4">
        {contacts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center text-muted-foreground">
            <User className="mb-3 h-10 w-10 opacity-40" />
            <p className="text-sm">No contacts yet.</p>
            <p className="text-xs">Click "Add Contact" to get started.</p>
          </div>
        ) : (
          <>
            {renderSection("⭐ Favorites", favorites)}
            {favorites.length > 0 && all.length > 0 && <Separator className="mb-4" />}
            {renderSection("👥 All Contacts", all)}
            {blocked.length > 0 && (favorites.length > 0 || all.length > 0) && (
              <Separator className="mb-4" />
            )}
            {renderSection("🚫 Blocked", blocked)}
          </>
        )}
      </div>

      {/* Add Contact dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Contact</DialogTitle>
          </DialogHeader>
          <div className="py-2">
            <UserSearch
              placeholder="Search by name or email…"
              onSelect={(user) => addMut.mutate({ user_id: user.user_id })}
            />
          </div>
        </DialogContent>
      </Dialog>

      {/* File picker */}
      <FilePickerDialog
        open={fileShareConvoId !== null}
        onClose={() => setFileShareConvoId(null)}
        onSelect={handleFileSelect}
        showPermission={true}
      />

      {/* Calendar picker */}
      <CalendarPickerDialog
        open={calShareConvoId !== null}
        onClose={() => setCalShareConvoId(null)}
        onSelect={handleCalendarSelect}
      />
    </div>
  );
}
