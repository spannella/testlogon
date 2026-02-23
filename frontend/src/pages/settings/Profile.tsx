import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Camera, Plus, X, ChevronDown, ChevronUp } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  getProfile,
  patchProfile,
  uploadProfilePhoto,
  getProfileAudit,
} from "@/api/endpoints/profile";

// ─── Schema ──────────────────────────────────────────────────────

const profileSchema = z.object({
  display_name: z.string().optional(),
  first_name: z.string().optional(),
  middle_name: z.string().optional(),
  last_name: z.string().optional(),
  title: z.string().optional(),
  description: z.string().optional(),
  birthday: z.string().optional(),
  gender: z.string().optional(),
  location: z.string().optional(),
  displayed_email: z.string().email().or(z.literal("")).optional(),
  displayed_telephone_number: z.string().optional(),
});

type ProfileFormValues = z.infer<typeof profileSchema>;

// ─── Component ───────────────────────────────────────────────────

export function Profile() {
  const queryClient = useQueryClient();
  const [auditOpen, setAuditOpen] = React.useState(false);

  // Languages managed outside RHF (dynamic list)
  const [languages, setLanguages] = React.useState<{ name: string; level: string }[]>([]);
  const [newLangName, setNewLangName] = React.useState("");
  const [newLangLevel, setNewLangLevel] = React.useState("beginner");

  const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
  });

  const auditQuery = useQuery({
    queryKey: ["profile-audit"],
    queryFn: getProfileAudit,
    enabled: auditOpen,
  });

  const form = useForm<ProfileFormValues>({
    resolver: zodResolver(profileSchema),
    defaultValues: {},
  });

  // Populate form when profile loads
  React.useEffect(() => {
    const p = profileQuery.data?.profile;
    if (!p) return;
    form.reset({
      display_name: p.display_name ?? "",
      first_name: p.first_name ?? "",
      middle_name: p.middle_name ?? "",
      last_name: p.last_name ?? "",
      title: p.title ?? "",
      description: p.description ?? "",
      birthday: p.birthday ?? "",
      gender: p.gender ?? "",
      location: p.location ?? "",
      displayed_email: p.displayed_email ?? "",
      displayed_telephone_number: p.displayed_telephone_number ?? "",
    });
    setLanguages(p.languages ?? []);
  }, [profileQuery.data, form]);

  const saveMutation = useMutation({
    mutationFn: (values: ProfileFormValues) => {
      return patchProfile({
        display_name: values.display_name,
        first_name: values.first_name,
        middle_name: values.middle_name,
        last_name: values.last_name,
        title: values.title,
        description: values.description,
        birthday: values.birthday,
        gender: values.gender,
        location: values.location,
        displayed_email: values.displayed_email,
        displayed_telephone_number: values.displayed_telephone_number,
        languages,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["profile"] });
      toast.success("Profile saved");
    },
    onError: () => {
      toast.error("Failed to save profile");
    },
  });

  const photoMutation = useMutation({
    mutationFn: ({ kind, file }: { kind: "profile" | "cover"; file: File }) =>
      uploadProfilePhoto(kind, file),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["profile"] });
      toast.success("Photo uploaded");
    },
    onError: () => {
      toast.error("Failed to upload photo");
    },
  });

  const handlePhotoChange = (kind: "profile" | "cover") => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";
    input.onchange = () => {
      const file = input.files?.[0];
      if (file) photoMutation.mutate({ kind, file });
    };
    input.click();
  };

  const addLanguage = () => {
    if (!newLangName.trim()) return;
    setLanguages((prev) => [...prev, { name: newLangName.trim(), level: newLangLevel }]);
    setNewLangName("");
    setNewLangLevel("beginner");
  };

  const removeLanguage = (index: number) => {
    setLanguages((prev) => prev.filter((_, i) => i !== index));
  };

  const onSubmit = (values: ProfileFormValues) => {
    saveMutation.mutate(values);
  };

  const profile = profileQuery.data?.profile;

  if (profileQuery.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-32 w-full rounded-xl" />
        <div className="space-y-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
      {/* Cover + Avatar */}
      <Card>
        <CardContent className="p-0">
          {/* Cover photo */}
          <div className="relative h-32 rounded-t-xl bg-muted sm:h-40">
            {profile?.cover_photo_url && (
              <img
                src={profile.cover_photo_url}
                alt="Cover"
                className="h-full w-full rounded-t-xl object-cover"
              />
            )}
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="absolute bottom-2 right-2"
              onClick={() => handlePhotoChange("cover")}
              disabled={photoMutation.isPending}
            >
              <Camera className="mr-1 h-3.5 w-3.5" />
              Cover
            </Button>
          </div>

          {/* Profile avatar */}
          <div className="flex items-end gap-4 px-6 -mt-10">
            <div className="relative">
              <Avatar className="h-20 w-20 border-4 border-background">
                <AvatarImage src={profile?.profile_photo_url} />
                <AvatarFallback className="text-lg">
                  {(profile?.display_name ?? profile?.first_name ?? "?").slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <Button
                type="button"
                variant="secondary"
                size="icon"
                className="absolute -bottom-1 -right-1 h-7 w-7 rounded-full"
                onClick={() => handlePhotoChange("profile")}
                disabled={photoMutation.isPending}
              >
                <Camera className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="pb-2">
              <p className="text-sm font-medium">{profile?.display_name ?? "Your Name"}</p>
              <p className="text-xs text-muted-foreground">{profile?.title ?? "No title"}</p>
            </div>
          </div>

          <div className="h-4" />
        </CardContent>
      </Card>

      {/* Basic info */}
      <Card>
        <CardHeader>
          <CardTitle>Basic Information</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="display_name">Display Name</Label>
            <Input id="display_name" {...form.register("display_name")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="first_name">First Name</Label>
            <Input id="first_name" {...form.register("first_name")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="middle_name">Middle Name</Label>
            <Input id="middle_name" {...form.register("middle_name")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="last_name">Last Name</Label>
            <Input id="last_name" {...form.register("last_name")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="title">Title</Label>
            <Input id="title" placeholder="e.g. Software Engineer" {...form.register("title")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="birthday">Birthday</Label>
            <Input id="birthday" type="date" {...form.register("birthday")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="gender">Gender</Label>
            <Select
              value={form.watch("gender") ?? ""}
              onValueChange={(v) => form.setValue("gender", v)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="male">Male</SelectItem>
                <SelectItem value="female">Female</SelectItem>
                <SelectItem value="non-binary">Non-binary</SelectItem>
                <SelectItem value="other">Other</SelectItem>
                <SelectItem value="prefer-not-to-say">Prefer not to say</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="location">Location</Label>
            <Input id="location" placeholder="City, Country" {...form.register("location")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="displayed_email">Email (public)</Label>
            <Input id="displayed_email" type="email" {...form.register("displayed_email")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="displayed_telephone_number">Phone (public)</Label>
            <Input id="displayed_telephone_number" {...form.register("displayed_telephone_number")} />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="description">Bio</Label>
            <Textarea
              id="description"
              rows={3}
              placeholder="Tell us about yourself..."
              {...form.register("description")}
            />
          </div>
        </CardContent>
      </Card>

      {/* Languages */}
      <Card>
        <CardHeader>
          <CardTitle>Languages</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {languages.length > 0 && (
            <div className="space-y-2">
              {languages.map((lang, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border px-3 py-2">
                  <span className="flex-1 text-sm font-medium">{lang.name}</span>
                  <span className="text-xs text-muted-foreground capitalize">{lang.level}</span>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 text-destructive"
                    onClick={() => removeLanguage(i)}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          )}
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1.5">
              <Label>Language</Label>
              <Input
                placeholder="e.g. English"
                value={newLangName}
                onChange={(e) => setNewLangName(e.target.value)}
              />
            </div>
            <div className="w-32 space-y-1.5">
              <Label>Level</Label>
              <Select value={newLangLevel} onValueChange={setNewLangLevel}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="beginner">Beginner</SelectItem>
                  <SelectItem value="intermediate">Intermediate</SelectItem>
                  <SelectItem value="advanced">Advanced</SelectItem>
                  <SelectItem value="native">Native</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={addLanguage}>
              <Plus className="mr-1 h-3.5 w-3.5" />
              Add
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Audit log */}
      <Card>
        <CardHeader>
          <button
            type="button"
            className="flex w-full items-center justify-between"
            onClick={() => setAuditOpen((o) => !o)}
          >
            <CardTitle>Audit Log</CardTitle>
            {auditOpen ? (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
        </CardHeader>
        {auditOpen && (
          <CardContent>
            {auditQuery.isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-6 w-full" />
                ))}
              </div>
            ) : (auditQuery.data?.audit ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">No audit records found.</p>
            ) : (
              <div className="max-h-64 space-y-2 overflow-y-auto">
                {(auditQuery.data?.audit ?? []).map((entry, i) => (
                  <div key={i} className="rounded border px-3 py-2 text-xs font-mono">
                    {JSON.stringify(entry, null, 2)}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        )}
      </Card>

      <Separator />

      {/* Save button */}
      <div className="flex justify-end">
        <Button type="submit" disabled={saveMutation.isPending}>
          {saveMutation.isPending ? "Saving..." : "Save Profile"}
        </Button>
      </div>
    </form>
  );
}
