import { useState } from "react";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card } from "@/components/ui/card";
import { addKey, listProviders } from "@/api/endpoints/llmKeys";
import type { LlmProviderInfo } from "@/api/types";
import { Eye, EyeOff } from "lucide-react";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function AddLlmKeyDialog({ open, onOpenChange }: Props) {
  const queryClient = useQueryClient();
  const [step, setStep] = useState<1 | 2>(1);
  const [selectedProvider, setSelectedProvider] = useState<LlmProviderInfo | null>(null);
  const [label, setLabel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [baseUrl, setBaseUrl] = useState("");
  const [modelPref, setModelPref] = useState("");
  const [rateLimit, setRateLimit] = useState("60");
  const [budget, setBudget] = useState("0");

  const { data: providersData } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: listProviders,
    enabled: open,
  });

  const addMut = useMutation({
    mutationFn: addKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["llm-keys"] });
      toast.success("LLM key added successfully");
      resetAndClose();
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to add key");
    },
  });

  function resetAndClose() {
    setStep(1);
    setSelectedProvider(null);
    setLabel("");
    setApiKey("");
    setShowKey(false);
    setBaseUrl("");
    setModelPref("");
    setRateLimit("60");
    setBudget("0");
    onOpenChange(false);
  }

  function handleSelectProvider(p: LlmProviderInfo) {
    setSelectedProvider(p);
    setStep(2);
  }

  function handleSubmit() {
    if (!selectedProvider) return;
    addMut.mutate({
      provider: selectedProvider.provider,
      label,
      api_key: apiKey,
      base_url: selectedProvider.provider === "custom" ? baseUrl : undefined,
      model_preference: modelPref || undefined,
      rate_limit_rpm: parseInt(rateLimit) || 60,
      monthly_budget_cents: parseInt(budget) || 0,
    });
  }

  const providers = providersData?.providers ?? [];

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) resetAndClose(); else onOpenChange(o); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{step === 1 ? "Select Provider" : "Configure Key"}</DialogTitle>
        </DialogHeader>

        {step === 1 && (
          <div className="grid grid-cols-2 gap-3 py-2">
            {providers.map((p) => (
              <Card
                key={p.provider}
                className="cursor-pointer p-4 hover:bg-accent transition-colors"
                onClick={() => handleSelectProvider(p)}
                data-testid={`provider-card-${p.provider}`}
              >
                <p className="font-medium text-sm">{p.display_name}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {p.models.length > 0 ? `${p.models.length} models` : "Custom endpoint"}
                </p>
              </Card>
            ))}
          </div>
        )}

        {step === 2 && selectedProvider && (
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="key-label">Label</Label>
              <Input
                id="key-label"
                placeholder="My API Key"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="api-key">API Key</Label>
              <div className="relative">
                <Input
                  id="api-key"
                  type={showKey ? "text" : "password"}
                  placeholder="sk-..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
                  onClick={() => setShowKey(!showKey)}
                >
                  {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            {selectedProvider.provider === "custom" && (
              <div className="space-y-2">
                <Label htmlFor="base-url">Base URL</Label>
                <Input
                  id="base-url"
                  placeholder="https://my-vllm.example.com/v1"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                />
              </div>
            )}

            {selectedProvider.models.length > 0 && (
              <div className="space-y-2">
                <Label>Model Preference</Label>
                <Select value={modelPref} onValueChange={setModelPref}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select model (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    {selectedProvider.models.map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="rate-limit">Rate Limit (RPM)</Label>
                <Input
                  id="rate-limit"
                  type="number"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="budget">Monthly Budget (cents)</Label>
                <Input
                  id="budget"
                  type="number"
                  placeholder="0 = unlimited"
                  value={budget}
                  onChange={(e) => setBudget(e.target.value)}
                />
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          {step === 2 && (
            <>
              <Button variant="outline" onClick={() => setStep(1)}>
                Back
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={!label || !apiKey || apiKey.length < 8 || addMut.isPending}
              >
                {addMut.isPending ? "Adding..." : "Add Key"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
