import { useState, useEffect, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  createTargeting,
  listTargeting,
  updateTargeting,
  deleteTargeting,
  estimateAudience,
} from "@/api/endpoints/ads";
import { api } from "@/api/client";
import type { AdTargeting, AudienceEstimate } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Target, Trash2, Users } from "lucide-react";

const AGE_RANGES = ["18-24", "25-34", "35-44", "45-54", "55+"];
const GENDERS = ["male", "female", "other"];
const DEVICE_TYPES = ["mobile", "desktop", "tablet"];
const CONTENT_TYPES = ["newsfeed", "broadcast", "vod"];
const COUNTRIES = [
  { code: "US", label: "United States" },
  { code: "CA", label: "Canada" },
  { code: "GB", label: "United Kingdom" },
  { code: "DE", label: "Germany" },
  { code: "FR", label: "France" },
  { code: "AU", label: "Australia" },
  { code: "JP", label: "Japan" },
  { code: "BR", label: "Brazil" },
  { code: "IN", label: "India" },
  { code: "MX", label: "Mexico" },
];

interface TargetingFormState {
  name: string;
  age_ranges: string[];
  genders: string[];
  country_codes: string[];
  device_types: string[];
  content_types: string[];
  content_categories: string[];
  new_user_only: boolean;
  creator_ids: string[];
  exclude_creator_ids: string[];
  exclude_categories: string[];
}

const emptyForm: TargetingFormState = {
  name: "Default",
  age_ranges: [],
  genders: [],
  country_codes: [],
  device_types: [],
  content_types: [],
  content_categories: [],
  new_user_only: false,
  creator_ids: [],
  exclude_creator_ids: [],
  exclude_categories: [],
};

export default function TargetingEditorPage() {
  const qc = useQueryClient();
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);
  const [form, setForm] = useState<TargetingFormState>({ ...emptyForm });
  const [editingTargetId, setEditingTargetId] = useState<string | null>(null);
  const [estimate, setEstimate] = useState<AudienceEstimate | null>(null);
  const [categoryInput, setCategory] = useState("");
  const [creatorInput, setCreatorInput] = useState("");
  const [exCreatorInput, setExCreatorInput] = useState("");
  const [exCategoryInput, setExCategoryInput] = useState("");

  // Fetch accounts then campaigns across all accounts
  const campaignsQ = useQuery({
    queryKey: ["ads", "campaigns"],
    queryFn: async () => {
      const accounts = await api.get<Array<{ account_id: string }>>("/ui/ads/accounts");
      const allCampaigns: Array<{ campaign_id: string; account_id: string; name: string }> = [];
      for (const acct of accounts) {
        const camps = await api.get<Array<{ campaign_id: string; account_id: string; name: string }>>(
          `/ui/ads/accounts/${acct.account_id}/campaigns`
        );
        allCampaigns.push(...camps);
      }
      return allCampaigns;
    },
    staleTime: 30_000,
  });

  const targetingQ = useQuery({
    queryKey: ["ads", "targeting", selectedCampaignId],
    queryFn: () => listTargeting(selectedCampaignId!),
    enabled: !!selectedCampaignId,
    staleTime: 30_000,
  });

  const createTargetingMut = useMutation({
    mutationFn: (body: Partial<AdTargeting>) =>
      createTargeting(selectedCampaignId!, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ads", "targeting", selectedCampaignId] });
      setForm({ ...emptyForm });
      setEditingTargetId(null);
    },
  });

  const updateTargetingMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<AdTargeting> }) =>
      updateTargeting(selectedCampaignId!, id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ads", "targeting", selectedCampaignId] });
      setForm({ ...emptyForm });
      setEditingTargetId(null);
    },
  });

  const deleteTargetingMut = useMutation({
    mutationFn: (id: string) => deleteTargeting(selectedCampaignId!, id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["ads", "targeting", selectedCampaignId] }),
  });

  // Debounced audience estimate
  const fetchEstimate = useCallback(async () => {
    if (!selectedCampaignId) return;
    const body: Record<string, unknown> = {};
    if (form.age_ranges.length) body.age_ranges = form.age_ranges;
    if (form.genders.length) body.genders = form.genders;
    if (form.country_codes.length) body.country_codes = form.country_codes;
    if (form.device_types.length) body.device_types = form.device_types;
    if (form.content_categories.length) body.content_categories = form.content_categories;
    if (form.creator_ids.length) body.creator_ids = form.creator_ids;
    try {
      const est = await estimateAudience(selectedCampaignId, body);
      setEstimate(est);
    } catch {
      // ignore
    }
  }, [selectedCampaignId, form]);

  useEffect(() => {
    const timer = setTimeout(fetchEstimate, 500);
    return () => clearTimeout(timer);
  }, [fetchEstimate]);

  const toggleListItem = (
    field: keyof TargetingFormState,
    value: string,
  ) => {
    setForm((prev) => {
      const arr = prev[field] as string[];
      return {
        ...prev,
        [field]: arr.includes(value)
          ? arr.filter((v) => v !== value)
          : [...arr, value],
      };
    });
  };

  const handleSave = () => {
    const body: Partial<AdTargeting> = { name: form.name, new_user_only: form.new_user_only };
    if (form.age_ranges.length) body.age_ranges = form.age_ranges;
    if (form.genders.length) body.genders = form.genders;
    if (form.country_codes.length) body.country_codes = form.country_codes;
    if (form.device_types.length) body.device_types = form.device_types;
    if (form.content_types.length) body.content_types = form.content_types;
    if (form.content_categories.length) body.content_categories = form.content_categories;
    if (form.creator_ids.length) body.creator_ids = form.creator_ids;
    if (form.exclude_creator_ids.length) body.exclude_creator_ids = form.exclude_creator_ids;
    if (form.exclude_categories.length) body.exclude_categories = form.exclude_categories;

    if (editingTargetId) {
      updateTargetingMut.mutate({ id: editingTargetId, body });
    } else {
      createTargetingMut.mutate(body);
    }
  };

  const startEdit = (t: AdTargeting) => {
    setEditingTargetId(t.target_set_id);
    setForm({
      name: t.name,
      age_ranges: t.age_ranges || [],
      genders: t.genders || [],
      country_codes: t.country_codes || [],
      device_types: t.device_types || [],
      content_types: t.content_types || [],
      content_categories: t.content_categories || [],
      new_user_only: t.new_user_only ?? false,
      creator_ids: t.creator_ids || [],
      exclude_creator_ids: t.exclude_creator_ids || [],
      exclude_categories: t.exclude_categories || [],
    });
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6" data-testid="targeting-editor">
      <div className="flex items-center gap-2">
        <Target className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Ad Targeting</h1>
      </div>

      {/* Campaign selector */}
      <Card>
        <CardHeader>
          <CardTitle>Campaigns</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {(campaignsQ.data || []).length === 0 && !campaignsQ.isLoading && (
            <p className="text-sm text-muted-foreground">No campaigns found. Create one via the Ads dashboard.</p>
          )}
          <div className="flex flex-wrap gap-2">
            {(campaignsQ.data || []).map((c) => (
              <Button
                key={c.campaign_id}
                variant={selectedCampaignId === c.campaign_id ? "default" : "outline"}
                size="sm"
                onClick={() => setSelectedCampaignId(c.campaign_id)}
              >
                {c.name}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {selectedCampaignId && (
        <>
          {/* Existing targeting sets */}
          {(targetingQ.data || []).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Targeting Sets</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(targetingQ.data || []).map((t) => (
                    <div
                      key={t.target_set_id}
                      className="flex items-center justify-between rounded border p-3"
                    >
                      <div>
                        <span className="font-medium">{t.name}</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {t.age_ranges?.map((r) => (
                            <Badge key={r} variant="secondary">{r}</Badge>
                          ))}
                          {t.country_codes?.map((c) => (
                            <Badge key={c} variant="secondary">{c}</Badge>
                          ))}
                          {t.device_types?.map((d) => (
                            <Badge key={d} variant="secondary">{d}</Badge>
                          ))}
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => startEdit(t)}
                        >
                          Edit
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteTargetingMut.mutate(t.target_set_id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Targeting form */}
          <Card>
            <CardHeader>
              <CardTitle>
                {editingTargetId ? "Edit Targeting Set" : "New Targeting Set"}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Name */}
              <div>
                <Label htmlFor="tgt-name">Name</Label>
                <Input
                  id="tgt-name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  data-testid="targeting-name"
                />
              </div>

              {/* Demographics */}
              <div>
                <h3 className="mb-2 font-semibold">Demographics</h3>
                <div className="space-y-3">
                  <div>
                    <Label>Age Ranges</Label>
                    <div className="flex flex-wrap gap-3 mt-1">
                      {AGE_RANGES.map((r) => (
                        <label key={r} className="flex items-center gap-1.5">
                          <Checkbox
                            checked={form.age_ranges.includes(r)}
                            onCheckedChange={() => toggleListItem("age_ranges", r)}
                            data-testid={`age-${r}`}
                          />
                          <span className="text-sm">{r}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Label>Gender</Label>
                    <div className="flex flex-wrap gap-3 mt-1">
                      {GENDERS.map((g) => (
                        <label key={g} className="flex items-center gap-1.5">
                          <Checkbox
                            checked={form.genders.includes(g)}
                            onCheckedChange={() => toggleListItem("genders", g)}
                            data-testid={`gender-${g}`}
                          />
                          <span className="text-sm capitalize">{g}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Geography */}
              <div>
                <h3 className="mb-2 font-semibold">Geography</h3>
                <Label>Countries</Label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {COUNTRIES.map((c) => (
                    <Button
                      key={c.code}
                      variant={form.country_codes.includes(c.code) ? "default" : "outline"}
                      size="sm"
                      onClick={() => toggleListItem("country_codes", c.code)}
                      data-testid={`country-${c.code}`}
                    >
                      {c.code}
                    </Button>
                  ))}
                </div>
                {form.country_codes.length > 0 && (
                  <div className="flex gap-1 mt-2">
                    {form.country_codes.map((c) => (
                      <Badge key={c} data-testid={`selected-country-${c}`}>{c}</Badge>
                    ))}
                  </div>
                )}
              </div>

              {/* Device types */}
              <div>
                <h3 className="mb-2 font-semibold">Devices</h3>
                <div className="flex flex-wrap gap-3">
                  {DEVICE_TYPES.map((d) => (
                    <label key={d} className="flex items-center gap-1.5">
                      <Checkbox
                        checked={form.device_types.includes(d)}
                        onCheckedChange={() => toggleListItem("device_types", d)}
                        data-testid={`device-${d}`}
                      />
                      <span className="text-sm capitalize">{d}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Content types */}
              <div>
                <h3 className="mb-2 font-semibold">Content Types</h3>
                <div className="flex flex-wrap gap-3">
                  {CONTENT_TYPES.map((ct) => (
                    <label key={ct} className="flex items-center gap-1.5">
                      <Checkbox
                        checked={form.content_types.includes(ct)}
                        onCheckedChange={() => toggleListItem("content_types", ct)}
                      />
                      <span className="text-sm capitalize">{ct}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Categories */}
              <div>
                <h3 className="mb-2 font-semibold">Content Categories</h3>
                <div className="flex gap-2">
                  <Input
                    placeholder="Add category (e.g. gaming)"
                    value={categoryInput}
                    onChange={(e) => setCategory(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && categoryInput.trim()) {
                        if (!form.content_categories.includes(categoryInput.trim())) {
                          setForm({
                            ...form,
                            content_categories: [...form.content_categories, categoryInput.trim()],
                          });
                        }
                        setCategory("");
                      }
                    }}
                  />
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {form.content_categories.map((c) => (
                    <Badge
                      key={c}
                      className="cursor-pointer"
                      onClick={() =>
                        setForm({
                          ...form,
                          content_categories: form.content_categories.filter((x) => x !== c),
                        })
                      }
                    >
                      {c} x
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Creator IDs */}
              <div>
                <h3 className="mb-2 font-semibold">Creator Targeting</h3>
                <div className="flex gap-2">
                  <Input
                    placeholder="Add creator ID"
                    value={creatorInput}
                    onChange={(e) => setCreatorInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && creatorInput.trim()) {
                        if (!form.creator_ids.includes(creatorInput.trim())) {
                          setForm({
                            ...form,
                            creator_ids: [...form.creator_ids, creatorInput.trim()],
                          });
                        }
                        setCreatorInput("");
                      }
                    }}
                  />
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {form.creator_ids.map((c) => (
                    <Badge
                      key={c}
                      className="cursor-pointer"
                      onClick={() =>
                        setForm({
                          ...form,
                          creator_ids: form.creator_ids.filter((x) => x !== c),
                        })
                      }
                    >
                      {c} x
                    </Badge>
                  ))}
                </div>
              </div>

              {/* New User Only */}
              <div className="flex items-center gap-2">
                <Switch
                  checked={form.new_user_only}
                  onCheckedChange={(v) => setForm({ ...form, new_user_only: v })}
                  data-testid="new-user-only"
                />
                <Label>New users only (joined within 30 days)</Label>
              </div>

              {/* Exclusions */}
              <div>
                <h3 className="mb-2 font-semibold">Exclusions</h3>
                <div className="space-y-3">
                  <div>
                    <Label>Exclude Creators</Label>
                    <div className="flex gap-2">
                      <Input
                        placeholder="Exclude creator ID"
                        value={exCreatorInput}
                        onChange={(e) => setExCreatorInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && exCreatorInput.trim()) {
                            if (!form.exclude_creator_ids.includes(exCreatorInput.trim())) {
                              setForm({
                                ...form,
                                exclude_creator_ids: [...form.exclude_creator_ids, exCreatorInput.trim()],
                              });
                            }
                            setExCreatorInput("");
                          }
                        }}
                      />
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {form.exclude_creator_ids.map((c) => (
                        <Badge
                          key={c}
                          variant="destructive"
                          className="cursor-pointer"
                          onClick={() =>
                            setForm({
                              ...form,
                              exclude_creator_ids: form.exclude_creator_ids.filter((x) => x !== c),
                            })
                          }
                        >
                          {c} x
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Label>Exclude Categories</Label>
                    <div className="flex gap-2">
                      <Input
                        placeholder="Exclude category"
                        value={exCategoryInput}
                        onChange={(e) => setExCategoryInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && exCategoryInput.trim()) {
                            if (!form.exclude_categories.includes(exCategoryInput.trim())) {
                              setForm({
                                ...form,
                                exclude_categories: [...form.exclude_categories, exCategoryInput.trim()],
                              });
                            }
                            setExCategoryInput("");
                          }
                        }}
                      />
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {form.exclude_categories.map((c) => (
                        <Badge
                          key={c}
                          variant="destructive"
                          className="cursor-pointer"
                          onClick={() =>
                            setForm({
                              ...form,
                              exclude_categories: form.exclude_categories.filter((x) => x !== c),
                            })
                          }
                        >
                          {c} x
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Audience estimate */}
              {estimate && (
                <Card data-testid="audience-estimate">
                  <CardContent className="flex items-center gap-3 pt-4">
                    <Users className="h-5 w-5 text-muted-foreground" />
                    <div>
                      <div className="text-lg font-semibold" data-testid="estimated-reach">
                        {estimate.estimated_reach.toLocaleString()}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        Estimated reach
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Actions */}
              <div className="flex gap-2">
                <Button onClick={handleSave} data-testid="save-targeting">
                  {editingTargetId ? "Update" : "Create"} Targeting Set
                </Button>
                {editingTargetId && (
                  <Button
                    variant="outline"
                    onClick={() => {
                      setEditingTargetId(null);
                      setForm({ ...emptyForm });
                    }}
                  >
                    Cancel
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
