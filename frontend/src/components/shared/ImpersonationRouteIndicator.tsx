import { Badge } from "@/components/ui/badge";
import { useImpersonationStore } from "@/stores/impersonationStore";

export default function ImpersonationRouteIndicator({ area }: { area: "billing" | "files" }) {
  const imp = useImpersonationStore();
  if (!imp.isActive()) return null;

  return (
    <Badge variant="outline" className="border-amber-500/60 text-amber-700 dark:text-amber-300">
      Impersonation active in {area}: acting as {imp.effectiveSub}
    </Badge>
  );
}
