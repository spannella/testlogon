import { Globe } from "lucide-react";
import { Button } from "@/components/ui/button";

interface GeoBlockedPageProps {
  country?: string;
}

/**
 * Full-page "Not Available in Your Region" message shown when a viewer
 * is geo-blocked from accessing content.
 */
export function GeoBlockedPage({ country }: GeoBlockedPageProps) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
      <Globe className="h-16 w-16 text-muted-foreground mb-4" />
      <h1 className="text-2xl font-bold">Not Available in Your Region</h1>
      <p className="mt-2 text-muted-foreground max-w-md">
        This content is not available in your current location
        {country ? ` (${country})` : ""}.
        The creator has restricted access to specific regions.
      </p>
      <Button
        variant="outline"
        className="mt-6"
        onClick={() => window.history.back()}
      >
        Go Back
      </Button>
    </div>
  );
}
