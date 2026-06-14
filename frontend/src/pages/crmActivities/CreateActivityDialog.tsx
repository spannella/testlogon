import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import {
  createCallLog,
  createTask,
  createNote,
  type CallDirection,
  type CallOutcome,
  type CallType,
  type CrmEntityType,
  type CrmTaskPriority,
  type CrmTaskStatus,
} from "@/api/endpoints/crmActivities";
import { localDateTimeToTs } from "./activityHelpers";

const ENTITY_TYPES: CrmEntityType[] = ["contact", "lead", "account", "opportunity"];

export interface PrefillLink {
  entity_type: CrmEntityType;
  entity_id: string;
}

interface CreateActivityDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Optional pre-filled CRM record link (used from the timeline page). */
  prefillLink?: PrefillLink;
  /** Restrict the dialog to a single tab. Defaults to all kinds. */
  defaultKind?: "call" | "task" | "note";
  onCreated?: () => void;
}

export function CreateActivityDialog({
  open,
  onOpenChange,
  prefillLink,
  defaultKind = "call",
  onCreated,
}: CreateActivityDialogProps) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<"call" | "task" | "note">(defaultKind);

  // Shared link
  const [linkType, setLinkType] = useState<CrmEntityType | "">(
    prefillLink?.entity_type ?? "",
  );
  const [linkId, setLinkId] = useState(prefillLink?.entity_id ?? "");

  // Call fields
  const [callSubject, setCallSubject] = useState("");
  const [callDescription, setCallDescription] = useState("");
  const [callDirection, setCallDirection] = useState<CallDirection>("outbound");
  const [callType, setCallType] = useState<CallType>("phone");
  const [callOutcome, setCallOutcome] = useState<CallOutcome>("connected");
  const [callDuration, setCallDuration] = useState("0");

  // Task fields
  const [taskSubject, setTaskSubject] = useState("");
  const [taskDescription, setTaskDescription] = useState("");
  const [taskStatus, setTaskStatus] = useState<CrmTaskStatus>("not_started");
  const [taskPriority, setTaskPriority] = useState<CrmTaskPriority>("medium");
  const [taskDue, setTaskDue] = useState("");

  // Note fields
  const [noteBody, setNoteBody] = useState("");

  const link = linkType
    ? { linked_entity_type: linkType, linked_entity_id: linkId.trim() || null }
    : {};

  const reset = () => {
    setCallSubject("");
    setCallDescription("");
    setCallDuration("0");
    setTaskSubject("");
    setTaskDescription("");
    setTaskDue("");
    setNoteBody("");
    if (!prefillLink) {
      setLinkType("");
      setLinkId("");
    }
  };

  const afterCreate = (msg: string) => {
    toast.success(msg);
    reset();
    void qc.invalidateQueries({ queryKey: ["crm-activities"] });
    onCreated?.();
    onOpenChange(false);
  };

  const errToast = (err: unknown) =>
    toast.error(err instanceof Error ? err.message : "Unable to create activity");

  const callMut = useMutation({
    mutationFn: () =>
      createCallLog({
        subject: callSubject.trim(),
        description: callDescription.trim() || undefined,
        direction: callDirection,
        call_type: callType,
        outcome: callOutcome,
        duration_seconds: Math.max(0, parseInt(callDuration, 10) || 0),
        ...link,
      }),
    onSuccess: () => afterCreate("Call logged"),
    onError: errToast,
  });

  const taskMut = useMutation({
    mutationFn: () =>
      createTask({
        subject: taskSubject.trim(),
        description: taskDescription.trim() || undefined,
        status: taskStatus,
        priority: taskPriority,
        due_date_ts: localDateTimeToTs(taskDue),
        ...link,
      }),
    onSuccess: () => afterCreate("Task created"),
    onError: errToast,
  });

  const noteMut = useMutation({
    mutationFn: () =>
      createNote({
        body: noteBody.trim(),
        ...link,
      }),
    onSuccess: () => afterCreate("Note added"),
    onError: errToast,
  });

  const submitting = callMut.isPending || taskMut.isPending || noteMut.isPending;

  const linkFields = (
    <div className="grid grid-cols-2 gap-3">
      <div className="space-y-1.5">
        <Label>Linked record type</Label>
        <Select
          value={linkType || "none"}
          onValueChange={(v) => setLinkType(v === "none" ? "" : (v as CrmEntityType))}
          disabled={!!prefillLink}
        >
          <SelectTrigger>
            <SelectValue placeholder="None" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">None</SelectItem>
            {ENTITY_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1.5">
        <Label>Record ID</Label>
        <Input
          value={linkId}
          onChange={(e) => setLinkId(e.target.value)}
          placeholder="e.g. contact id"
          disabled={!!prefillLink || !linkType}
        />
      </div>
    </div>
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Log activity</DialogTitle>
          <DialogDescription>
            Record a call, task, or note
            {prefillLink ? ` against ${prefillLink.entity_type} ${prefillLink.entity_id}` : ""}.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={kind} onValueChange={(v) => setKind(v as typeof kind)}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="call">Call</TabsTrigger>
            <TabsTrigger value="task">Task</TabsTrigger>
            <TabsTrigger value="note">Note</TabsTrigger>
          </TabsList>

          {/* ── Call ── */}
          <TabsContent value="call" className="space-y-3 pt-2">
            <div className="space-y-1.5">
              <Label htmlFor="call-subject">Subject</Label>
              <Input
                id="call-subject"
                value={callSubject}
                onChange={(e) => setCallSubject(e.target.value)}
                placeholder="Call subject"
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label>Direction</Label>
                <Select value={callDirection} onValueChange={(v) => setCallDirection(v as CallDirection)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="outbound">Outbound</SelectItem>
                    <SelectItem value="inbound">Inbound</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Type</Label>
                <Select value={callType} onValueChange={(v) => setCallType(v as CallType)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="phone">Phone</SelectItem>
                    <SelectItem value="audio">Audio</SelectItem>
                    <SelectItem value="video">Video</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="call-duration">Duration (s)</Label>
                <Input
                  id="call-duration"
                  type="number"
                  min={0}
                  value={callDuration}
                  onChange={(e) => setCallDuration(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Outcome</Label>
              <Select value={callOutcome} onValueChange={(v) => setCallOutcome(v as CallOutcome)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="connected">Connected</SelectItem>
                  <SelectItem value="not_connected">Not connected</SelectItem>
                  <SelectItem value="left_message">Left message</SelectItem>
                  <SelectItem value="wrong_number">Wrong number</SelectItem>
                  <SelectItem value="busy">Busy</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="call-desc">Notes</Label>
              <Textarea
                id="call-desc"
                value={callDescription}
                onChange={(e) => setCallDescription(e.target.value)}
                rows={3}
              />
            </div>
            {linkFields}
            <DialogFooter>
              <Button
                onClick={() => callMut.mutate()}
                disabled={submitting || !callSubject.trim()}
              >
                {callMut.isPending ? "Logging…" : "Log call"}
              </Button>
            </DialogFooter>
          </TabsContent>

          {/* ── Task ── */}
          <TabsContent value="task" className="space-y-3 pt-2">
            <div className="space-y-1.5">
              <Label htmlFor="task-subject">Subject</Label>
              <Input
                id="task-subject"
                value={taskSubject}
                onChange={(e) => setTaskSubject(e.target.value)}
                placeholder="Task subject"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Status</Label>
                <Select value={taskStatus} onValueChange={(v) => setTaskStatus(v as CrmTaskStatus)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="not_started">Not started</SelectItem>
                    <SelectItem value="in_progress">In progress</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="deferred">Deferred</SelectItem>
                    <SelectItem value="waiting">Waiting</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Priority</Label>
                <Select value={taskPriority} onValueChange={(v) => setTaskPriority(v as CrmTaskPriority)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="urgent">Urgent</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="task-due">Due date</Label>
              <Input
                id="task-due"
                type="datetime-local"
                value={taskDue}
                onChange={(e) => setTaskDue(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="task-desc">Description</Label>
              <Textarea
                id="task-desc"
                value={taskDescription}
                onChange={(e) => setTaskDescription(e.target.value)}
                rows={3}
              />
            </div>
            {linkFields}
            <DialogFooter>
              <Button
                onClick={() => taskMut.mutate()}
                disabled={submitting || !taskSubject.trim()}
              >
                {taskMut.isPending ? "Creating…" : "Create task"}
              </Button>
            </DialogFooter>
          </TabsContent>

          {/* ── Note ── */}
          <TabsContent value="note" className="space-y-3 pt-2">
            <div className="space-y-1.5">
              <Label htmlFor="note-body">Note</Label>
              <Textarea
                id="note-body"
                value={noteBody}
                onChange={(e) => setNoteBody(e.target.value)}
                rows={5}
                placeholder="Write a note…"
              />
            </div>
            {linkFields}
            <DialogFooter>
              <Button
                onClick={() => noteMut.mutate()}
                disabled={submitting || !noteBody.trim()}
              >
                {noteMut.isPending ? "Saving…" : "Add note"}
              </Button>
            </DialogFooter>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
