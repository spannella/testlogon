import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Wrench, Plus, Trash2, RotateCcw, Pencil } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import { NotEnabledState, isNotEnabled } from "./NotEnabledState";
import {
  STUDIO_ENTITY_TYPES,
  STUDIO_FIELD_TYPES,
  createStudioField,
  deactivateStudioField,
  listStudioFields,
  updateStudioField,
  type StudioField,
  type StudioFieldType,
} from "@/api/endpoints/crmStudio";

const NUMERIC_TYPES: StudioFieldType[] = ["integer", "decimal"];
const PICKLIST_TYPES: StudioFieldType[] = ["picklist", "multi_picklist"];

function CreateFieldDialog({
  entityType,
  open,
  onOpenChange,
  onCreated,
}: {
  entityType: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: () => void;
}) {
  const [fieldKey, setFieldKey] = useState("");
  const [label, setLabel] = useState("");
  const [fieldType, setFieldType] = useState<StudioFieldType>("text");
  const [required, setRequired] = useState(false);
  const [picklistName, setPicklistName] = useState("");
  const [maxLength, setMaxLength] = useState("1000");
  const [minValue, setMinValue] = useState("");
  const [maxValue, setMaxValue] = useState("");
  const [sortOrder, setSortOrder] = useState("0");

  const reset = () => {
    setFieldKey("");
    setLabel("");
    setFieldType("text");
    setRequired(false);
    setPicklistName("");
    setMaxLength("1000");
    setMinValue("");
    setMaxValue("");
    setSortOrder("0");
  };

  const createMut = useMutation({
    mutationFn: () =>
      createStudioField(entityType, {
        field_key: fieldKey.trim(),
        label: label.trim(),
        field_type: fieldType,
        required,
        picklist_name: PICKLIST_TYPES.includes(fieldType) ? picklistName.trim() || null : null,
        max_length: Number(maxLength) || 1000,
        min_value: NUMERIC_TYPES.includes(fieldType) && minValue !== "" ? Number(minValue) : null,
        max_value: NUMERIC_TYPES.includes(fieldType) && maxValue !== "" ? Number(maxValue) : null,
        sort_order: Number(sortOrder) || 0,
      }),
    onSuccess: () => {
      toast.success("Field created");
      reset();
      onOpenChange(false);
      onCreated();
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        toast.error("A field with that key already exists");
      } else {
        toast.error(e instanceof ApiError ? e.detail : "Failed to create field");
      }
    },
  });

  const keyValid = /^[a-z][a-z0-9_]{2,49}$/.test(fieldKey.trim());

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New custom field</DialogTitle>
          <DialogDescription>
            Add a custom field to the <span className="font-medium capitalize">{entityType}</span>{" "}
            entity.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="f-key">Field key</Label>
            <Input
              id="f-key"
              value={fieldKey}
              onChange={(e) => setFieldKey(e.target.value)}
              placeholder="lowercase_snake_case"
            />
            {fieldKey && !keyValid && (
              <p className="text-xs text-destructive">
                Must be lowercase, start with a letter, 3–50 chars (a–z, 0–9, _).
              </p>
            )}
          </div>
          <div className="space-y-1">
            <Label htmlFor="f-label">Label</Label>
            <Input id="f-label" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Type</Label>
              <Select value={fieldType} onValueChange={(v) => setFieldType(v as StudioFieldType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STUDIO_FIELD_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="f-sort">Sort order</Label>
              <Input
                id="f-sort"
                type="number"
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value)}
              />
            </div>
          </div>

          {PICKLIST_TYPES.includes(fieldType) && (
            <div className="space-y-1">
              <Label htmlFor="f-picklist">Picklist name (required)</Label>
              <Input
                id="f-picklist"
                value={picklistName}
                onChange={(e) => setPicklistName(e.target.value)}
                placeholder="picklist identifier"
              />
            </div>
          )}

          {fieldType === "text" && (
            <div className="space-y-1">
              <Label htmlFor="f-maxlen">Max length</Label>
              <Input
                id="f-maxlen"
                type="number"
                value={maxLength}
                onChange={(e) => setMaxLength(e.target.value)}
              />
            </div>
          )}

          {NUMERIC_TYPES.includes(fieldType) && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="f-min">Min value</Label>
                <Input
                  id="f-min"
                  type="number"
                  value={minValue}
                  onChange={(e) => setMinValue(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="f-max">Max value</Label>
                <Input
                  id="f-max"
                  type="number"
                  value={maxValue}
                  onChange={(e) => setMaxValue(e.target.value)}
                />
              </div>
            </div>
          )}

          <label className="flex items-center gap-2 text-sm">
            <Switch checked={required} onCheckedChange={setRequired} />
            Required field
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!keyValid || !label.trim() || createMut.isPending}
          >
            Create field
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EditFieldDialog({
  field,
  open,
  onOpenChange,
  onSaved,
}: {
  field: StudioField | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSaved: () => void;
}) {
  const [label, setLabel] = useState(field?.label ?? "");
  const [required, setRequired] = useState(field?.required ?? false);
  const [sortOrder, setSortOrder] = useState(String(field?.sort_order ?? 0));

  // Re-sync when field changes (dialog reused per row).
  const [lastKey, setLastKey] = useState<string | null>(null);
  if (field && field.field_key !== lastKey) {
    setLastKey(field.field_key);
    setLabel(field.label);
    setRequired(field.required);
    setSortOrder(String(field.sort_order));
  }

  const saveMut = useMutation({
    mutationFn: () =>
      updateStudioField(field!.entity_type, field!.field_key, {
        label: label.trim(),
        required,
        sort_order: Number(sortOrder) || 0,
      }),
    onSuccess: () => {
      toast.success("Field updated");
      onOpenChange(false);
      onSaved();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to update"),
  });

  if (!field) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit field</DialogTitle>
          <DialogDescription>
            <span className="font-mono">{field.field_key}</span> ({field.field_type})
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="e-label">Label</Label>
            <Input id="e-label" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="e-sort">Sort order</Label>
            <Input
              id="e-sort"
              type="number"
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value)}
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={required} onCheckedChange={setRequired} />
            Required field
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function CrmStudioPage() {
  const qc = useQueryClient();
  const [entityType, setEntityType] = useState<string>(STUDIO_ENTITY_TYPES[0]!);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editField, setEditField] = useState<StudioField | null>(null);

  const fieldsQuery = useQuery({
    queryKey: ["crm-studio", "fields", entityType, includeInactive],
    queryFn: () => listStudioFields(entityType, { include_inactive: includeInactive, limit: 500 }),
    retry: false,
  });

  const deactivateMut = useMutation({
    mutationFn: (fieldKey: string) => deactivateStudioField(entityType, fieldKey),
    onSuccess: () => {
      toast.success("Field deactivated");
      qc.invalidateQueries({ queryKey: ["crm-studio", "fields", entityType] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to deactivate"),
  });

  const reactivateMut = useMutation({
    mutationFn: (fieldKey: string) =>
      updateStudioField(entityType, fieldKey, { reactivate: true }),
    onSuccess: () => {
      toast.success("Field reactivated");
      qc.invalidateQueries({ queryKey: ["crm-studio", "fields", entityType] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to reactivate"),
  });

  const fields = fieldsQuery.data?.fields ?? [];

  const renderBody = () => {
    if (fieldsQuery.isError) {
      const err = fieldsQuery.error;
      if (isNotEnabled(err)) return <NotEnabledState feature="Studio custom fields" />;
      // 403 on include_inactive requires ROOT — surface a hint but still allow active view.
      if (err instanceof ApiError && err.status === 403) {
        return (
          <NotEnabledState feature="Studio custom fields" status={403} />
        );
      }
      return <NotEnabledState feature="Studio custom fields" status={(err as ApiError)?.status} />;
    }

    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Fields</CardTitle>
          <CardDescription>
            {fields.length} field{fields.length === 1 ? "" : "s"} on{" "}
            <span className="capitalize">{entityType}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {fieldsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {!fieldsQuery.isLoading && fields.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No custom fields defined for this entity.
            </p>
          )}
          {fields.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Key</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Required</TableHead>
                  <TableHead>Sort</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {fields.map((f) => (
                  <TableRow key={f.field_key} className={f.is_active ? "" : "opacity-60"}>
                    <TableCell className="font-mono text-xs">{f.field_key}</TableCell>
                    <TableCell>{f.label}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{f.field_type}</Badge>
                      {f.picklist_name && (
                        <span className="ml-1 text-xs text-muted-foreground">
                          ({f.picklist_name})
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {f.required ? <Badge variant="secondary">required</Badge> : "—"}
                    </TableCell>
                    <TableCell>{f.sort_order}</TableCell>
                    <TableCell>
                      {f.is_active ? (
                        <Badge variant="secondary">active</Badge>
                      ) : (
                        <Badge variant="outline">inactive</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {f.is_active ? (
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="ghost" onClick={() => setEditField(f)}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              if (confirm(`Deactivate field "${f.field_key}"?`))
                                deactivateMut.mutate(f.field_key);
                            }}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      ) : (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => reactivateMut.mutate(f.field_key)}
                        >
                          <RotateCcw className="mr-1 h-3.5 w-3.5" /> Reactivate
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Studio — Custom Fields"
        description="Define custom fields per CRM entity. Field creation and edits require root."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" /> New field
          </Button>
        }
      />

      <Card>
        <CardContent className="flex flex-wrap items-end gap-4 pt-6">
          <div className="space-y-1">
            <Label className="flex items-center gap-1 text-xs">
              <Wrench className="h-3.5 w-3.5" /> Entity
            </Label>
            <Select value={entityType} onValueChange={setEntityType}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STUDIO_ENTITY_TYPES.map((et) => (
                  <SelectItem key={et} value={et} className="capitalize">
                    {et}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <Switch checked={includeInactive} onCheckedChange={setIncludeInactive} />
            Include inactive (root only)
          </label>
        </CardContent>
      </Card>

      {renderBody()}

      <CreateFieldDialog
        entityType={entityType}
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() =>
          qc.invalidateQueries({ queryKey: ["crm-studio", "fields", entityType] })
        }
      />
      <EditFieldDialog
        field={editField}
        open={!!editField}
        onOpenChange={(v) => {
          if (!v) setEditField(null);
        }}
        onSaved={() =>
          qc.invalidateQueries({ queryKey: ["crm-studio", "fields", entityType] })
        }
      />
    </div>
  );
}
