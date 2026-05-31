import { useQuery } from "@tanstack/react-query";
import { Info } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { whyThisAd } from "@/api/endpoints/ads";

interface WhyThisAdDialogProps {
  creativeId: string;
  open: boolean;
  onClose: () => void;
}

export function WhyThisAdDialog({ creativeId, open, onClose }: WhyThisAdDialogProps) {
  const { data, isLoading } = useQuery({
    queryKey: ["why-this-ad", creativeId],
    queryFn: () => whyThisAd(creativeId),
    enabled: open && !!creativeId,
    staleTime: 300_000, // 5 minutes
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent data-testid="why-this-ad-dialog">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Info className="h-5 w-5" />
            Why this ad?
          </DialogTitle>
          <DialogDescription>
            Information about why you are seeing this ad.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-2">
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : data ? (
            <>
              <p className="text-sm font-medium">{data.reason}</p>
              <p className="text-sm text-muted-foreground">{data.note}</p>
              {data.categories && data.categories.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {data.categories.map((cat) => (
                    <span
                      key={cat}
                      className="inline-flex items-center rounded-full bg-muted px-2.5 py-0.5 text-xs font-medium"
                    >
                      {cat}
                    </span>
                  ))}
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">
              This ad was shown based on your general activity on the platform.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
