import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Upload, Trash2, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { listSshKeys, generateSshKey, uploadSshKey, deleteSshKey } from "@/api/endpoints/sshKeys";
import type { SshKeyOut } from "@/api/types";

function formatDate(ts: number): string {
  if (!ts) return "Never";
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function truncateFingerprint(fp: string): string {
  if (fp.length <= 20) return fp;
  return fp.substring(0, 20) + "...";
}

export default function SshKeyManagerPage() {
  const queryClient = useQueryClient();
  const [generateOpen, setGenerateOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SshKeyOut | null>(null);
  const [showPublicKey, setShowPublicKey] = useState<SshKeyOut | null>(null);
  const [copied, setCopied] = useState(false);

  // Generate form state
  const [genLabel, setGenLabel] = useState("");
  const [genKeyType, setGenKeyType] = useState<"ed25519" | "rsa">("ed25519");
  const [genKeyBits, setGenKeyBits] = useState(4096);

  // Upload form state
  const [upLabel, setUpLabel] = useState("");
  const [upPem, setUpPem] = useState("");
  const [upPassphrase, setUpPassphrase] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["ssh-keys"],
    queryFn: listSshKeys,
    staleTime: 30_000,
  });

  const generateMut = useMutation({
    mutationFn: generateSshKey,
    onSuccess: (key) => {
      queryClient.invalidateQueries({ queryKey: ["ssh-keys"] });
      setGenerateOpen(false);
      setGenLabel("");
      setShowPublicKey(key);
      toast.success(`${key.key_type.toUpperCase()} key "${key.label}" created.`);
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to generate key");
    },
  });

  const uploadMut = useMutation({
    mutationFn: uploadSshKey,
    onSuccess: (key) => {
      queryClient.invalidateQueries({ queryKey: ["ssh-keys"] });
      setUploadOpen(false);
      setUpLabel("");
      setUpPem("");
      setUpPassphrase("");
      toast.success(`${key.key_type.toUpperCase()} key "${key.label}" stored.`);
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to upload key");
    },
  });

  const deleteMut = useMutation({
    mutationFn: (keyId: string) => deleteSshKey(keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ssh-keys"] });
      setDeleteTarget(null);
      toast.success("Key deleted");
    },
  });

  const keys = data?.keys ?? [];

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            <CardTitle>SSH Keys</CardTitle>
          </div>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => setGenerateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" /> Generate Key
            </Button>
            <Button size="sm" variant="outline" onClick={() => setUploadOpen(true)}>
              <Upload className="h-4 w-4 mr-1" /> Upload Key
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground text-sm">Loading...</p>
          ) : keys.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No SSH keys stored. Generate a new key pair or upload an existing one.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Fingerprint</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((key) => (
                  <TableRow key={key.key_id}>
                    <TableCell className="font-medium">{key.label}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {key.key_type.toUpperCase()} {key.key_type === "rsa" ? key.key_bits : ""}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {truncateFingerprint(key.public_key_fingerprint)}
                    </TableCell>
                    <TableCell>{formatDate(key.created_at)}</TableCell>
                    <TableCell>{formatDate(key.last_used_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setShowPublicKey(key);
                            setCopied(false);
                          }}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-destructive"
                          onClick={() => setDeleteTarget(key)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Generate Key Dialog */}
      <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate SSH Key</DialogTitle>
            <DialogDescription>
              Generate a new SSH key pair. The private key is encrypted and stored securely.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="gen-label">Label</Label>
              <Input
                id="gen-label"
                placeholder="e.g. Production Key"
                value={genLabel}
                onChange={(e) => setGenLabel(e.target.value)}
              />
            </div>
            <div>
              <Label>Key Type</Label>
              <div className="flex gap-4 mt-1">
                <label className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="keyType"
                    value="ed25519"
                    checked={genKeyType === "ed25519"}
                    onChange={() => setGenKeyType("ed25519")}
                  />
                  Ed25519 (recommended)
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="keyType"
                    value="rsa"
                    checked={genKeyType === "rsa"}
                    onChange={() => setGenKeyType("rsa")}
                  />
                  RSA
                </label>
              </div>
            </div>
            {genKeyType === "rsa" && (
              <div>
                <Label htmlFor="gen-bits">Key Size (bits)</Label>
                <select
                  id="gen-bits"
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={genKeyBits}
                  onChange={(e) => setGenKeyBits(Number(e.target.value))}
                >
                  <option value={2048}>2048</option>
                  <option value={4096}>4096</option>
                  <option value={8192}>8192</option>
                </select>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGenerateOpen(false)}>Cancel</Button>
            <Button
              onClick={() =>
                generateMut.mutate({
                  label: genLabel,
                  key_type: genKeyType,
                  key_bits: genKeyType === "rsa" ? genKeyBits : undefined,
                })
              }
              disabled={!genLabel.trim() || generateMut.isPending}
            >
              {generateMut.isPending ? "Generating..." : "Generate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Upload Key Dialog */}
      <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Upload SSH Key</DialogTitle>
            <DialogDescription>
              Your private key is encrypted with KMS before storage. It is never exposed after upload.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="up-label">Label</Label>
              <Input
                id="up-label"
                placeholder="e.g. My Server Key"
                value={upLabel}
                onChange={(e) => setUpLabel(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="up-pem">Private Key (PEM)</Label>
              <Textarea
                id="up-pem"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...&#10;-----END OPENSSH PRIVATE KEY-----"
                className="font-mono text-xs"
                rows={8}
                value={upPem}
                onChange={(e) => setUpPem(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="up-passphrase">Passphrase (optional)</Label>
              <Input
                id="up-passphrase"
                type="password"
                placeholder="Leave empty if key is not passphrase-protected"
                value={upPassphrase}
                onChange={(e) => setUpPassphrase(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>Cancel</Button>
            <Button
              onClick={() =>
                uploadMut.mutate({
                  label: upLabel,
                  private_key_pem: upPem,
                  passphrase: upPassphrase || undefined,
                })
              }
              disabled={!upLabel.trim() || !upPem.trim() || uploadMut.isPending}
            >
              {uploadMut.isPending ? "Uploading..." : "Upload"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Public Key Dialog */}
      <Dialog open={!!showPublicKey} onOpenChange={() => setShowPublicKey(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Public Key</DialogTitle>
            <DialogDescription>
              Add this public key to ~/.ssh/authorized_keys on your target hosts.
            </DialogDescription>
          </DialogHeader>
          {showPublicKey && (
            <div className="space-y-3">
              <div className="text-sm text-muted-foreground">
                Fingerprint: <span className="font-mono">{showPublicKey.public_key_fingerprint}</span>
              </div>
              <Textarea
                readOnly
                className="font-mono text-xs"
                rows={4}
                value={showPublicKey.public_key_openssh}
              />
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleCopy(showPublicKey.public_key_openssh)}
              >
                {copied ? <Check className="h-4 w-4 mr-1" /> : <Copy className="h-4 w-4 mr-1" />}
                {copied ? "Copied" : "Copy to clipboard"}
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete SSH Key</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteTarget?.label}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.key_id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
