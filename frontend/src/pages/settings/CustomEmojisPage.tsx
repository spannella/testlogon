// MSG-007: Custom emoji management page.
//
// Users upload/list/delete personal custom emojis. Admins additionally get a
// global-emoji manager (the global list query returns 403 for non-admins and
// is silently hidden).
import { useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Smile, Trash2, Upload, Star } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/api/client";
import {
  uploadCustomEmoji,
  listMyCustomEmojis,
  deleteCustomEmoji,
  uploadGlobalEmoji,
  listGlobalEmojis,
  deleteGlobalEmoji,
  type UploadCustomEmojiBody,
} from "@/api/endpoints/customEmojis";
import type { CustomEmoji } from "@/api/types";

const MAX_FILE_SIZE = 262144; // 256KB
const MAX_DIM = 128;

interface UploadFormState {
  shortcode: string;
  name: string;
  alt_text: string;
  category: string;
  file: File | null;
}

const EMPTY_FORM: UploadFormState = {
  shortcode: "",
  name: "",
  alt_text: "",
  category: "Uncategorized",
  file: null,
};

function useEmojiUploadForm(
  uploader: (body: UploadCustomEmojiBody) => Promise<CustomEmoji>,
  invalidateKeys: unknown[][],
) {
  const qc = useQueryClient();
  const [form, setForm] = useState<UploadFormState>(EMPTY_FORM);
  const fileRef = useRef<HTMLInputElement>(null);

  const mut = useMutation({
    mutationFn: async () => {
      if (!form.file) throw new Error("Please choose an image file.");
      if (form.file.size > MAX_FILE_SIZE) {
        throw new Error("File size exceeds maximum of 256KB.");
      }
      return uploader({
        shortcode: form.shortcode.trim().toLowerCase(),
        name: form.name.trim() || form.shortcode.trim(),
        alt_text: form.alt_text.trim(),
        category: form.category.trim() || "Uncategorized",
        file: form.file,
      });
    },
    onSuccess: () => {
      toast.success("Emoji uploaded");
      setForm(EMPTY_FORM);
      if (fileRef.current) fileRef.current.value = "";
      invalidateKeys.forEach((key) => qc.invalidateQueries({ queryKey: key }));
    },
    onError: (err) => {
      const msg =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Upload failed";
      toast.error(msg);
    },
  });

  return { form, setForm, fileRef, mut };
}

function UploadForm({
  testid,
  uploader,
  invalidateKeys,
}: {
  testid: string;
  uploader: (body: UploadCustomEmojiBody) => Promise<CustomEmoji>;
  invalidateKeys: unknown[][];
}) {
  const { form, setForm, fileRef, mut } = useEmojiUploadForm(uploader, invalidateKeys);

  return (
    <form
      data-testid={testid}
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        mut.mutate();
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor={`${testid}-shortcode`}>Shortcode</Label>
          <Input
            id={`${testid}-shortcode`}
            data-testid={`${testid}-shortcode`}
            value={form.shortcode}
            onChange={(e) => setForm((f) => ({ ...f, shortcode: e.target.value }))}
            placeholder="my_cat"
            pattern="[a-z0-9_]{2,32}"
            required
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${testid}-name`}>Name</Label>
          <Input
            id={`${testid}-name`}
            data-testid={`${testid}-name`}
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="My Cat"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${testid}-alt`}>Alt text</Label>
          <Input
            id={`${testid}-alt`}
            value={form.alt_text}
            onChange={(e) => setForm((f) => ({ ...f, alt_text: e.target.value }))}
            placeholder="A cute orange cat"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${testid}-category`}>Category</Label>
          <Input
            id={`${testid}-category`}
            value={form.category}
            onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}
            placeholder="Pets"
          />
        </div>
      </div>
      <div className="space-y-1">
        <Label htmlFor={`${testid}-file`}>Image (PNG or GIF, max 256KB, max {MAX_DIM}x{MAX_DIM})</Label>
        <Input
          id={`${testid}-file`}
          data-testid={`${testid}-file`}
          ref={fileRef}
          type="file"
          accept="image/png,image/gif"
          onChange={(e) => setForm((f) => ({ ...f, file: e.target.files?.[0] ?? null }))}
        />
      </div>
      <Button type="submit" data-testid={`${testid}-submit`} disabled={mut.isPending}>
        <Upload className="mr-2 h-4 w-4" />
        {mut.isPending ? "Uploading..." : "Upload"}
      </Button>
    </form>
  );
}

function EmojiGrid({
  emojis,
  onDelete,
  emptyLabel,
}: {
  emojis: CustomEmoji[];
  onDelete: (emoji: CustomEmoji) => void;
  emptyLabel: string;
}) {
  if (emojis.length === 0) {
    return <p className="text-sm text-muted-foreground">{emptyLabel}</p>;
  }
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4">
      {emojis.map((ce) => (
        <div
          key={ce.emoji_id}
          data-testid={`emoji-card-${ce.shortcode}`}
          className="flex flex-col items-center gap-1 rounded-lg border border-border p-3"
        >
          <img
            src={ce.image_url}
            alt={ce.alt_text || ce.shortcode}
            className="h-12 w-12 object-contain"
          />
          <span className="text-xs font-mono text-muted-foreground">:{ce.shortcode}:</span>
          <span className="text-[10px] text-muted-foreground">{ce.category}</span>
          <Button
            variant="ghost"
            size="sm"
            data-testid={`emoji-delete-${ce.shortcode}`}
            onClick={() => onDelete(ce)}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="mr-1 h-3 w-3" />
            Delete
          </Button>
        </div>
      ))}
    </div>
  );
}

export default function CustomEmojisPage() {
  const qc = useQueryClient();

  const { data: myData } = useQuery({
    queryKey: ["custom-emojis"],
    queryFn: listMyCustomEmojis,
  });
  const personal = (myData?.emojis ?? []).filter((e) => e.owner_scope.startsWith("USER#"));
  const personalCount = myData?.personal_count ?? personal.length;

  const { data: globalData, isError: globalError } = useQuery({
    queryKey: ["custom-emojis", "global-admin"],
    queryFn: listGlobalEmojis,
    retry: false,
  });
  const isAdmin = !globalError && globalData != null;

  const deletePersonal = useMutation({
    mutationFn: (emojiId: string) => deleteCustomEmoji(emojiId),
    onSuccess: () => {
      toast.success("Emoji deleted");
      qc.invalidateQueries({ queryKey: ["custom-emojis"] });
    },
    onError: () => toast.error("Failed to delete emoji"),
  });

  const deleteGlobal = useMutation({
    mutationFn: (emojiId: string) => deleteGlobalEmoji(emojiId),
    onSuccess: () => {
      toast.success("Global emoji deleted");
      qc.invalidateQueries({ queryKey: ["custom-emojis"] });
    },
    onError: () => toast.error("Failed to delete global emoji"),
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4" data-testid="custom-emojis-page">
      <div className="flex items-center gap-2">
        <Smile className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Custom Emojis</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Upload a personal emoji</CardTitle>
        </CardHeader>
        <CardContent>
          <UploadForm
            testid="personal-upload"
            uploader={uploadCustomEmoji}
            invalidateKeys={[["custom-emojis"]]}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            My emojis{" "}
            <span className="text-sm font-normal text-muted-foreground">
              ({personalCount} / 100 used)
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmojiGrid
            emojis={personal}
            onDelete={(ce) => deletePersonal.mutate(ce.emoji_id)}
            emptyLabel="You haven't uploaded any custom emojis yet."
          />
        </CardContent>
      </Card>

      {isAdmin && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Star className="h-4 w-4" /> Upload a global emoji (admin)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <UploadForm
                testid="global-upload"
                uploader={uploadGlobalEmoji}
                invalidateKeys={[["custom-emojis"], ["custom-emojis", "global-admin"]]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Global emojis</CardTitle>
            </CardHeader>
            <CardContent>
              <EmojiGrid
                emojis={globalData?.emojis ?? []}
                onDelete={(ce) => deleteGlobal.mutate(ce.emoji_id)}
                emptyLabel="No global emojis yet."
              />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
