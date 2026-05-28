import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2, Copy, Wifi, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  listInputs,
  addInput,
  removeInput,
  activateInput,
  deactivateInput,
} from "@/api/endpoints/broadcast-inputs";
import type { BroadcastInput, BroadcastInputList } from "@/api/types";

interface InputManagerProps {
  sessionId: string;
  isBroadcaster: boolean;
}

export default function InputManager({ sessionId, isBroadcaster }: InputManagerProps) {
  const queryClient = useQueryClient();
  const [newLabel, setNewLabel] = useState("");

  const inputsQuery = useQuery({
    queryKey: ["broadcast", "inputs", sessionId],
    queryFn: () => listInputs(sessionId),
    refetchInterval: 5000,
  });

  const data: BroadcastInputList | undefined = inputsQuery.data;
  const inputs: BroadcastInput[] = data?.inputs ?? [];

  const addMut = useMutation({
    mutationFn: () => addInput(sessionId, { input_type: "guest", label: newLabel || "Input" }),
    onSuccess: (result) => {
      toast.success(`Input added: ${result.input_id}`);
      setNewLabel("");
      queryClient.invalidateQueries({ queryKey: ["broadcast", "inputs", sessionId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to add input"),
  });

  const removeMut = useMutation({
    mutationFn: (inputId: string) => removeInput(sessionId, inputId),
    onSuccess: () => {
      toast.success("Input removed");
      queryClient.invalidateQueries({ queryKey: ["broadcast", "inputs", sessionId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to remove input"),
  });

  const activateMut = useMutation({
    mutationFn: (inputId: string) => activateInput(sessionId, inputId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "inputs", sessionId] });
    },
  });

  const deactivateMut = useMutation({
    mutationFn: (inputId: string) => deactivateInput(sessionId, inputId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "inputs", sessionId] });
    },
  });

  const copyUrl = (url: string) => {
    navigator.clipboard.writeText(url);
    toast.success("Copied to clipboard");
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          Video Inputs
          <Badge variant="outline">{inputs.length}/{data?.max_inputs ?? 4}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {inputs.map((inp) => (
          <div
            key={inp.input_id}
            className="flex items-center justify-between rounded-md border p-2 text-sm"
            data-testid={`input-${inp.input_id}`}
          >
            <div className="flex items-center gap-2">
              {inp.is_live ? (
                <Wifi className="h-4 w-4 text-green-500" />
              ) : (
                <WifiOff className="h-4 w-4 text-muted-foreground" />
              )}
              <span className="font-medium">{inp.label || inp.input_type}</span>
              <Badge variant={inp.is_live ? "default" : "secondary"} className="text-xs">
                {inp.is_live ? "Live" : "Offline"}
              </Badge>
            </div>
            {isBroadcaster && (
              <div className="flex items-center gap-1">
                {inp.ingest_url && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => copyUrl(inp.ingest_url!)}
                    title="Copy RTMP URL"
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={() =>
                    inp.is_live
                      ? deactivateMut.mutate(inp.input_id)
                      : activateMut.mutate(inp.input_id)
                  }
                  title={inp.is_live ? "Deactivate" : "Activate"}
                >
                  {inp.is_live ? (
                    <WifiOff className="h-3 w-3" />
                  ) : (
                    <Wifi className="h-3 w-3" />
                  )}
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-destructive"
                  onClick={() => removeMut.mutate(inp.input_id)}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            )}
          </div>
        ))}

        {isBroadcaster && inputs.length < (data?.max_inputs ?? 4) && (
          <div className="flex gap-2">
            <Input
              placeholder="Label (optional)"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              className="flex-1"
            />
            <Button
              size="sm"
              onClick={() => addMut.mutate()}
              disabled={addMut.isPending}
            >
              <Plus className="h-4 w-4 mr-1" />
              Add Input
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
