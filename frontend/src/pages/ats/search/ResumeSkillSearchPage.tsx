/**
 * RSK-003 + RSK-004 — Resume & Skill Search Page (ats/search)
 *
 * Two-tab interface:
 *   Tab 1 — "Resume Search" (RSK-003): full-text keyword search over extracted
 *             résumé content. Returns ranked candidate hits.
 *   Tab 2 — "Skill Search" (RSK-004): multi-skill AND/OR search over the forward
 *             skill index. Returns ranked candidates or job orders.
 *
 * Gated by S.candidates_enabled — shows a clear "not enabled" state on 404.
 */

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  FileSearch,
  GitMerge,
  Search,
  Users,
  Briefcase,
  ChevronRight,
  Star,
} from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";

import {
  searchResumes,
  searchCandidatesBySkills,
  searchJobOrdersBySkills,
  isRskNotEnabled,
  type ResumeSearchResultItem,
  type CandidateMatchOut,
  type JobOrderMatchOut,
} from "@/api/endpoints/resumeSkills";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function pct(score: number): string {
  return `${Math.round(score * 100)}%`;
}

// ─── Not-enabled guard ────────────────────────────────────────────────────────

function RskNotEnabled() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[40vh] gap-4 text-center">
      <FileSearch className="h-12 w-12 text-muted-foreground" />
      <h2 className="text-xl font-semibold">Search Not Available</h2>
      <p className="text-muted-foreground max-w-sm">
        ATS résumé/skill search is not currently enabled. Ask your administrator
        to enable{" "}
        <code className="text-xs bg-muted px-1 py-0.5 rounded">
          CANDIDATES_ENABLED
        </code>
        .
      </p>
    </div>
  );
}

// ─── Resume search tab ────────────────────────────────────────────────────────

function ResumeSearchTab() {
  const [query, setQuery] = useState("");
  const [searchAll, setSearchAll] = useState(false);
  const [notEnabled, setNotEnabled] = useState(false);

  const searchMut = useMutation({
    mutationFn: () =>
      searchResumes({ q: query.trim(), limit: 25, all: searchAll || undefined }),
    onError: (e: unknown) => {
      if (isRskNotEnabled(e)) {
        setNotEnabled(true);
      } else {
        toast.error((e as Error).message || "Search failed");
      }
    },
  });

  if (notEnabled) return <RskNotEnabled />;

  const results = searchMut.data?.items ?? [];
  const hasMore = searchMut.data?.has_more ?? false;
  const totalEst = searchMut.data?.total_estimate ?? 0;

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Search keywords against extracted résumé text. Multiple words are
        ANDed together.
      </p>

      {/* Search bar */}
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <Label htmlFor="resume-q" className="mb-1 block text-xs text-muted-foreground">
            Keywords
          </Label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              id="resume-q"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='e.g. "python kubernetes react"'
              className="pl-9"
              onKeyDown={(e) => {
                if (e.key === "Enter" && query.trim().length >= 2)
                  searchMut.mutate();
              }}
            />
          </div>
        </div>
        <Button
          onClick={() => searchMut.mutate()}
          disabled={query.trim().length < 2 || searchMut.isPending}
        >
          {searchMut.isPending ? "Searching…" : "Search"}
        </Button>
      </div>

      <div className="flex items-center gap-2">
        <Switch
          id="search-all"
          checked={searchAll}
          onCheckedChange={setSearchAll}
        />
        <Label htmlFor="search-all" className="text-sm cursor-pointer">
          Search all owners (admin only)
        </Label>
      </div>

      {/* Results */}
      {searchMut.isPending && (
        <div className="space-y-2">
          {[1, 2, 3].map((n) => (
            <Skeleton key={n} className="h-14 w-full" />
          ))}
        </div>
      )}

      {searchMut.isSuccess && (
        <>
          <p className="text-xs text-muted-foreground">
            {totalEst} candidate{totalEst !== 1 ? "s" : ""} found
            {hasMore ? " (showing top 25)" : ""}
            {searchMut.data?.query
              ? ` for "${searchMut.data.query}"`
              : ""}
          </p>

          {results.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                No résumés matched your query.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {results.map((item: ResumeSearchResultItem) => (
                <ResumeHitCard key={item.candidate_id} item={item} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ResumeHitCard({ item }: { item: ResumeSearchResultItem }) {
  return (
    <Card className="hover:bg-accent/30 transition-colors">
      <CardContent className="py-3 flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="font-medium truncate">{item.name_snippet || "Candidate"}</p>
          <p className="text-xs text-muted-foreground">
            ID: {item.candidate_id} · Updated {fmt(item.updated_at)}
          </p>
        </div>
        <Link to={`/ats/candidates/${item.candidate_id}`}>
          <Button size="sm" variant="ghost">
            <ChevronRight className="h-4 w-4" />
          </Button>
        </Link>
      </CardContent>
    </Card>
  );
}

// ─── Skill search tab ─────────────────────────────────────────────────────────

type SkillTarget = "candidates" | "job_orders";

function SkillSearchTab() {
  const [skillInput, setSkillInput] = useState("");
  const [matchMode, setMatchMode] = useState<"all" | "any">("all");
  const [target, setTarget] = useState<SkillTarget>("candidates");
  const [requiredOnly, setRequiredOnly] = useState(false);
  const [notEnabled, setNotEnabled] = useState(false);

  const candidateMut = useMutation({
    mutationFn: () =>
      searchCandidatesBySkills({
        skill_ids: skillInput.trim(),
        match: matchMode,
        limit: 50,
      }),
    onError: (e: unknown) => {
      if (isRskNotEnabled(e)) setNotEnabled(true);
      else toast.error((e as Error).message || "Search failed");
    },
  });

  const jobOrderMut = useMutation({
    mutationFn: () =>
      searchJobOrdersBySkills({
        skill_ids: skillInput.trim(),
        match: matchMode,
        required_only: requiredOnly || undefined,
        limit: 50,
      }),
    onError: (e: unknown) => {
      if (isRskNotEnabled(e)) setNotEnabled(true);
      else toast.error((e as Error).message || "Search failed");
    },
  });

  if (notEnabled) return <RskNotEnabled />;

  const runSearch = () => {
    if (!skillInput.trim()) return;
    if (target === "candidates") candidateMut.mutate();
    else jobOrderMut.mutate();
  };

  const isPending =
    target === "candidates" ? candidateMut.isPending : jobOrderMut.isPending;
  const isSuccess =
    target === "candidates" ? candidateMut.isSuccess : jobOrderMut.isSuccess;
  const results =
    target === "candidates"
      ? (candidateMut.data?.items as CandidateMatchOut[] | undefined) ?? []
      : (jobOrderMut.data?.items as JobOrderMatchOut[] | undefined) ?? [];
  const queriedIds =
    target === "candidates"
      ? candidateMut.data?.query_skill_ids
      : jobOrderMut.data?.query_skill_ids;
  const total =
    target === "candidates"
      ? candidateMut.data?.total
      : jobOrderMut.data?.total;

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Find candidates or job orders by skill tags. Enter skill names or IDs
        (comma-separated).
      </p>

      {/* Controls */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <Label className="mb-1 block text-xs text-muted-foreground">
            Skills (comma-separated)
          </Label>
          <div className="relative">
            <GitMerge className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={skillInput}
              onChange={(e) => setSkillInput(e.target.value)}
              placeholder="python, aws, react"
              className="pl-9"
              onKeyDown={(e) => {
                if (e.key === "Enter") runSearch();
              }}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <Label className="mb-1 block text-xs text-muted-foreground">
              Match mode
            </Label>
            <Select
              value={matchMode}
              onValueChange={(v) => setMatchMode(v as "all" | "any")}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All skills (AND)</SelectItem>
                <SelectItem value="any">Any skill (OR)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="mb-1 block text-xs text-muted-foreground">
              Search in
            </Label>
            <Select
              value={target}
              onValueChange={(v) => setTarget(v as SkillTarget)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="candidates">Candidates</SelectItem>
                <SelectItem value="job_orders">Job Orders</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {target === "job_orders" && (
        <div className="flex items-center gap-2">
          <Switch
            id="req-only"
            checked={requiredOnly}
            onCheckedChange={setRequiredOnly}
          />
          <Label htmlFor="req-only" className="text-sm cursor-pointer">
            Required skills only
          </Label>
        </div>
      )}

      <Button
        onClick={runSearch}
        disabled={!skillInput.trim() || isPending}
        className="w-full sm:w-auto"
      >
        {isPending ? "Searching…" : "Search"}
      </Button>

      {/* Queried IDs chip row */}
      {isSuccess && queriedIds && queriedIds.length > 0 && (
        <div className="flex flex-wrap gap-1">
          <span className="text-xs text-muted-foreground self-center">
            Queried:
          </span>
          {queriedIds.map((id) => (
            <Badge key={id} variant="secondary" className="text-xs">
              {id}
            </Badge>
          ))}
        </div>
      )}

      {/* Results */}
      {isPending && (
        <div className="space-y-2">
          {[1, 2, 3].map((n) => (
            <Skeleton key={n} className="h-16 w-full" />
          ))}
        </div>
      )}

      {isSuccess && (
        <>
          <p className="text-xs text-muted-foreground">
            {total ?? results.length} result
            {(total ?? results.length) !== 1 ? "s" : ""}
          </p>

          {results.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                No matches found for the given skills.
              </CardContent>
            </Card>
          ) : target === "candidates" ? (
            <CandidateResultsList
              items={results as CandidateMatchOut[]}
            />
          ) : (
            <JobOrderResultsList
              items={results as JobOrderMatchOut[]}
            />
          )}
        </>
      )}
    </div>
  );
}

function CandidateResultsList({ items }: { items: CandidateMatchOut[] }) {
  return (
    <div className="space-y-2">
      {items.map((c) => (
        <Card key={c.candidate_id} className="hover:bg-accent/30 transition-colors">
          <CardContent className="py-3 flex items-center justify-between gap-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                <p className="font-medium truncate">{c.name || c.candidate_id}</p>
                <MatchScoreBadge score={c.match_score} />
              </div>
              {c.email && (
                <p className="text-xs text-muted-foreground mt-0.5">
                  {c.email}
                </p>
              )}
              <MatchedSkillsRow ids={c.matched_skill_ids} />
            </div>
            <Link to={`/ats/candidates/${c.candidate_id}`}>
              <Button size="sm" variant="ghost">
                <ChevronRight className="h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function JobOrderResultsList({ items }: { items: JobOrderMatchOut[] }) {
  return (
    <div className="space-y-2">
      {items.map((j) => (
        <Card key={j.job_order_id} className="hover:bg-accent/30 transition-colors">
          <CardContent className="py-3 flex items-center justify-between gap-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <Briefcase className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                <p className="font-medium truncate">{j.title || j.job_order_id}</p>
                <MatchScoreBadge score={j.match_score} />
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <Badge variant="outline" className="text-xs">
                  {j.status}
                </Badge>
              </div>
              <MatchedSkillsRow ids={j.matched_skill_ids} />
            </div>
            <Link to={`/ats/job-orders/${j.job_order_id}`}>
              <Button size="sm" variant="ghost">
                <ChevronRight className="h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function MatchScoreBadge({ score }: { score: number }) {
  const label = pct(score);
  const colorClass =
    score >= 0.8
      ? "bg-green-100 text-green-800 border-green-200"
      : score >= 0.5
        ? "bg-amber-100 text-amber-800 border-amber-200"
        : "bg-muted text-muted-foreground";
  return (
    <span
      className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-xs font-medium border ${colorClass}`}
    >
      <Star className="h-2.5 w-2.5" />
      {label}
    </span>
  );
}

function MatchedSkillsRow({ ids }: { ids: string[] }) {
  if (!ids.length) return null;
  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {ids.map((id) => (
        <span
          key={id}
          className="px-1.5 py-0.5 bg-primary/10 text-primary rounded text-xs"
        >
          {id}
        </span>
      ))}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ResumeSkillSearchPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Résumé & Skill Search"
        description="Search candidates by résumé content or by skill tags."
        actions={
          <Badge variant="secondary" className="text-xs">
            <FileSearch className="h-3 w-3 mr-1" />
            RSK-003 / RSK-004
          </Badge>
        }
      />

      <Tabs defaultValue="resume">
        <TabsList className="mb-4">
          <TabsTrigger value="resume" className="gap-2">
            <FileSearch className="h-4 w-4" />
            Resume Search
          </TabsTrigger>
          <TabsTrigger value="skills" className="gap-2">
            <GitMerge className="h-4 w-4" />
            Skill Search
          </TabsTrigger>
        </TabsList>

        <TabsContent value="resume">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Full-Text Résumé Search</CardTitle>
              <CardDescription>
                Keywords are matched against the extracted plain-text content of
                uploaded résumés (PDF / DOCX). Results are ordered by
                best-match score.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResumeSearchTab />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="skills">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Skill-Based Search</CardTitle>
              <CardDescription>
                Find candidates or job orders that have specific skill tags
                assigned. Use AND to require all skills, OR to match any.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SkillSearchTab />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
