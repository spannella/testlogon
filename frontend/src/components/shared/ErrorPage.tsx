import { useNavigate } from "react-router-dom";
import { Compass, Lock, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ErrorPageProps {
  status?: number;
  title?: string;
  description?: string;
}

export function ErrorPage({ status = 404, title, description }: ErrorPageProps) {
  const navigate = useNavigate();

  const config = getErrorConfig(status, title, description);

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center px-4 text-center">
      <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-muted">
        {config.icon}
      </div>
      <h1 className="text-4xl font-bold tracking-tight">{config.status}</h1>
      <h2 className="mt-2 text-xl font-semibold">{config.title}</h2>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">
        {config.description}
      </p>
      <Button className="mt-6" onClick={() => navigate("/")}>
        Back to Dashboard
      </Button>
    </div>
  );
}

function getErrorConfig(status: number, title?: string, description?: string) {
  switch (status) {
    case 403:
      return {
        status: "403",
        icon: <Lock className="h-10 w-10 text-muted-foreground" />,
        title: title ?? "Permission Denied",
        description:
          description ??
          "You don't have permission to access this page. Contact your administrator if you believe this is a mistake.",
      };
    case 404:
      return {
        status: "404",
        icon: <Compass className="h-10 w-10 text-muted-foreground" />,
        title: title ?? "Page Not Found",
        description:
          description ??
          "The page you're looking for doesn't exist or has been moved. Check the URL and try again.",
      };
    default:
      return {
        status: String(status),
        icon: <AlertTriangle className="h-10 w-10 text-muted-foreground" />,
        title: title ?? "Something Went Wrong",
        description:
          description ??
          "An unexpected error occurred. Please try again later or contact support if the problem persists.",
      };
  }
}
