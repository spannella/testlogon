import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { useToast } from "@/components/ui/use-toast";
import { createGroup } from "@/api/endpoints/groups";

const schema = z.object({
  name: z.string().min(3, "Name must be at least 3 characters").max(100),
  description: z.string().max(2000).default(""),
  visibility: z.enum(["public", "private"]).default("public"),
  topic: z.string().max(50).optional(),
});

type FormValues = z.infer<typeof schema>;

interface CreateGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}

export default function CreateGroupDialog({
  open,
  onOpenChange,
  onCreated,
}: CreateGroupDialogProps) {
  const { toast } = useToast();

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: "",
      description: "",
      visibility: "public",
      topic: "",
    },
  });

  const mutation = useMutation({
    mutationFn: (values: FormValues) =>
      createGroup({
        name: values.name,
        description: values.description,
        visibility: values.visibility,
        topic: values.topic || undefined,
      }),
    onSuccess: () => {
      toast({ title: "Group created successfully" });
      form.reset();
      onOpenChange(false);
      onCreated();
    },
    onError: (err: any) => {
      toast({
        title: "Failed to create group",
        description: err?.response?.data?.detail || "Unknown error",
        variant: "destructive",
      });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Create Group</DialogTitle>
        </DialogHeader>
        <form
          onSubmit={form.handleSubmit((v) => mutation.mutate(v))}
          className="space-y-4"
        >
          <div className="space-y-2">
            <Label htmlFor="group-name">Name</Label>
            <Input
              id="group-name"
              placeholder="Group name"
              {...form.register("name")}
            />
            {form.formState.errors.name && (
              <p className="text-sm text-destructive">
                {form.formState.errors.name.message}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="group-description">Description</Label>
            <Textarea
              id="group-description"
              placeholder="What is this group about?"
              rows={3}
              {...form.register("description")}
            />
          </div>

          <div className="space-y-2">
            <Label>Visibility</Label>
            <RadioGroup
              defaultValue="public"
              onValueChange={(v) =>
                form.setValue("visibility", v as "public" | "private")
              }
            >
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="public" id="vis-public" />
                <Label htmlFor="vis-public">Public - Anyone can join</Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="private" id="vis-private" />
                <Label htmlFor="vis-private">
                  Private - Requires approval to join
                </Label>
              </div>
            </RadioGroup>
          </div>

          <div className="space-y-2">
            <Label htmlFor="group-topic">Topic (optional)</Label>
            <Input
              id="group-topic"
              placeholder="e.g., photography, gaming"
              {...form.register("topic")}
            />
          </div>

          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Creating..." : "Create Group"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
