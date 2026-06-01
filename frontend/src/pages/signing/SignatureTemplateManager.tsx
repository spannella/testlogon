import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  type SignatureTemplateField,
  createSignatureTemplateVersion,
  listSignatureTemplates,
  listSignatureTemplateVersions,
} from "@/api/endpoints/signatureTemplates";

const NOTARY_TEMPLATE_FIELDS: SignatureTemplateField[] = [
  { id: "full_name", type: "text", label: "Full Legal Name", required: true },
  { id: "signature", type: "signature", label: "Signature", required: true },
  { id: "date_signed", type: "date", label: "Date", required: true },
  { id: "notary_stamp", type: "notary_stamp", label: "Notary Stamp", required: true },
];

/**
 * SignatureTemplateManager (KYC-007)
 *
 * Lists versioned signature templates, lets an admin publish a new version
 * (which never mutates in-flight packets), and surfaces the notary_stamp field
 * type. Used on the Signing page.
 */
export function SignatureTemplateManager() {
  const queryClient = useQueryClient();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const templatesQuery = useQuery({
    queryKey: ["signature-templates", "list"],
    queryFn: listSignatureTemplates,
    staleTime: 60_000,
  });

  const versionsQuery = useQuery({
    queryKey: ["signature-templates", "versions", selectedKey],
    queryFn: () => listSignatureTemplateVersions(selectedKey as string),
    enabled: !!selectedKey,
  });

  const createMutation = useMutation({
    mutationFn: () =>
      createSignatureTemplateVersion({
        template_key: "notary_consent",
        display_name: "Notary Consent Form",
        description: "Standard KYC notary consent with notary stamp.",
        fields: NOTARY_TEMPLATE_FIELDS,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["signature-templates"] });
    },
  });

  const templates = templatesQuery.data?.templates ?? [];

  return (
    <Card data-testid="signature-template-manager">
      <CardHeader>
        <CardTitle>Signature Templates</CardTitle>
        <CardDescription>
          Versioned document templates. Publishing a new version leaves existing
          signed packets pinned to their original terms.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            onClick={() => createMutation.mutate()}
            disabled={createMutation.isPending}
            data-testid="publish-notary-template"
          >
            {createMutation.isPending ? "Publishing…" : "Publish Notary Template Version"}
          </Button>
        </div>

        {templatesQuery.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading templates…</p>
        ) : templates.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="no-templates">
            No templates published yet.
          </p>
        ) : (
          <ul className="space-y-2" data-testid="template-list">
            {templates.map((tpl) => (
              <li
                key={tpl.template_key}
                className="flex items-center justify-between rounded-md border p-3"
                data-testid={`template-row-${tpl.template_key}`}
              >
                <div>
                  <p className="font-medium">{tpl.display_name}</p>
                  <p className="text-xs text-muted-foreground">{tpl.template_key}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary" data-testid={`template-version-${tpl.template_key}`}>
                    v{tpl.version}
                  </Badge>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setSelectedKey(tpl.template_key)}
                  >
                    History
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}

        {selectedKey && versionsQuery.data ? (
          <div className="rounded-md border p-3" data-testid="template-versions">
            <p className="mb-2 text-sm font-medium">Versions of {selectedKey}</p>
            <ul className="space-y-1">
              {versionsQuery.data.versions.map((v) => (
                <li key={v.version} className="flex items-center justify-between text-sm">
                  <span>v{v.version}</span>
                  <span className="text-muted-foreground">
                    {v.fields.some((f) => f.type === "notary_stamp")
                      ? "includes notary stamp"
                      : `${v.fields.length} fields`}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export default SignatureTemplateManager;
