import { useEffect, type ReactNode } from "react";
import { useTenantStore } from "@/stores/tenantStore";
import type { TenantBranding } from "@/api/types";

async function fetchBranding(): Promise<TenantBranding> {
  const resp = await fetch("/ui/tenant/branding");
  if (!resp.ok) throw new Error("Failed to fetch tenant branding");
  return resp.json();
}

export default function TenantBrandingProvider({
  children,
}: {
  children: ReactNode;
}) {
  const { setBranding, setLoading, setError } = useTenantStore();

  useEffect(() => {
    setLoading(true);
    fetchBranding()
      .then((data) => {
        setBranding(data);

        // Apply CSS vars
        const root = document.documentElement;
        root.style.setProperty("--tenant-primary", data.primary_color);
        root.style.setProperty("--tenant-accent", data.accent_color);

        // Apply favicon if provided
        if (data.favicon_url) {
          let link = document.querySelector(
            "link[rel='icon']",
          ) as HTMLLinkElement | null;
          if (!link) {
            link = document.createElement("link");
            link.rel = "icon";
            document.head.appendChild(link);
          }
          link.href = data.favicon_url;
        }
      })
      .catch((err) => {
        setError(err.message || "Unknown error");
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return <>{children}</>;
}
