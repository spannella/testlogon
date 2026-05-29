import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

const campaignSchema = z.object({
  name: z.string().min(1, "Name is required").max(200),
  objective: z.enum(["awareness", "traffic", "conversions"]),
  budget_cents: z.number().min(100, "Minimum budget is $1.00"),
  budget_type: z.enum(["daily", "lifetime"]),
});

type CampaignFormData = z.infer<typeof campaignSchema>;

interface CampaignEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: CampaignFormData) => void;
  isPending?: boolean;
  defaultValues?: Partial<CampaignFormData>;
  title?: string;
}

export default function CampaignEditor({
  open,
  onOpenChange,
  onSubmit,
  isPending = false,
  defaultValues,
  title = "Create Campaign",
}: CampaignEditorProps) {
  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
    reset,
  } = useForm<CampaignFormData>({
    resolver: zodResolver(campaignSchema),
    defaultValues: {
      name: defaultValues?.name ?? "",
      objective: defaultValues?.objective ?? "awareness",
      budget_cents: defaultValues?.budget_cents ?? 1000,
      budget_type: defaultValues?.budget_type ?? "daily",
    },
  });

  const objective = watch("objective");
  const budgetType = watch("budget_type");

  const handleFormSubmit = (data: CampaignFormData) => {
    onSubmit(data);
    reset();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-4 py-2">
          <div>
            <Label htmlFor="campaign_name">Campaign Name</Label>
            <Input
              id="campaign_name"
              {...register("name")}
              placeholder="Summer Sale Campaign"
            />
            {errors.name && (
              <p className="text-sm text-destructive mt-1">{errors.name.message}</p>
            )}
          </div>

          <div>
            <Label>Objective</Label>
            <Select
              value={objective}
              onValueChange={(v) => setValue("objective", v as CampaignFormData["objective"])}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="awareness">Awareness</SelectItem>
                <SelectItem value="traffic">Traffic</SelectItem>
                <SelectItem value="conversions">Conversions</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label htmlFor="budget">Budget (cents)</Label>
            <Input
              id="budget"
              type="number"
              {...register("budget_cents", { valueAsNumber: true })}
              min={100}
            />
            {errors.budget_cents && (
              <p className="text-sm text-destructive mt-1">
                {errors.budget_cents.message}
              </p>
            )}
          </div>

          <div>
            <Label>Budget Type</Label>
            <Select
              value={budgetType}
              onValueChange={(v) => setValue("budget_type", v as CampaignFormData["budget_type"])}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="lifetime">Lifetime</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending ? "Saving..." : "Save"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
