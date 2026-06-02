// MSG-006: Shared emoji picker.
//
// Categorized, searchable emoji picker with a recents section and a skin-tone
// selector. Reusable across messaging (ComposeBar) and newsfeed (CreatePost).
// Selecting an emoji calls `onSelect(emoji)` and records it in the emojiStore
// recents list.

import * as React from "react";
import { Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  EMOJI_CATEGORIES,
  EMOJI_BY_CATEGORY,
  SKIN_TONES,
  applySkinTone,
  searchEmojis,
  type EmojiCategory,
  type EmojiEntry,
} from "@/data/emoji-data";
import { useEmojiStore } from "@/stores/emojiStore";

export interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose?: () => void;
}

export function EmojiPicker({ onSelect, onClose }: EmojiPickerProps) {
  const [rawQuery, setRawQuery] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [activeCategory, setActiveCategory] = React.useState<EmojiCategory>("smileys");
  const [toneOpen, setToneOpen] = React.useState(false);

  const recentEmojis = useEmojiStore((s) => s.recentEmojis);
  const skinTone = useEmojiStore((s) => s.skinTone);
  const addRecent = useEmojiStore((s) => s.addRecent);
  const setSkinTone = useEmojiStore((s) => s.setSkinTone);

  const gridRef = React.useRef<HTMLDivElement>(null);
  const sectionRefs = React.useRef<Record<string, HTMLDivElement | null>>({});

  // Debounce the search query (150ms) per spec.
  React.useEffect(() => {
    const id = window.setTimeout(() => setQuery(rawQuery.trim().toLowerCase()), 150);
    return () => window.clearTimeout(id);
  }, [rawQuery]);

  const searchResults: EmojiEntry[] = React.useMemo(
    () => (query ? searchEmojis(query) : []),
    [query],
  );

  const handlePick = React.useCallback(
    (entry: EmojiEntry) => {
      const final = entry.skinToneSupport ? applySkinTone(entry.emoji, skinTone) : entry.emoji;
      addRecent(final);
      onSelect(final);
    },
    [skinTone, addRecent, onSelect],
  );

  const scrollToCategory = (cat: EmojiCategory) => {
    setActiveCategory(cat);
    const el = sectionRefs.current[cat];
    if (el && gridRef.current) {
      gridRef.current.scrollTo({ top: el.offsetTop - gridRef.current.offsetTop, behavior: "smooth" });
    }
  };

  const currentTone = SKIN_TONES.find((t) => t.modifier === skinTone) ?? SKIN_TONES[0];

  const renderEmojiButton = (entry: EmojiEntry, keyPrefix: string) => {
    const display = entry.skinToneSupport ? applySkinTone(entry.emoji, skinTone) : entry.emoji;
    return (
      <button
        key={`${keyPrefix}-${entry.shortcode}`}
        type="button"
        title={entry.name}
        aria-label={entry.name}
        data-emoji={display}
        onClick={() => handlePick(entry)}
        className="flex h-8 w-8 items-center justify-center rounded text-xl hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
      >
        {display}
      </button>
    );
  };

  return (
    <div
      data-testid="emoji-picker"
      role="dialog"
      aria-label="Emoji picker"
      className="flex w-[320px] flex-col"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onClose?.();
        }
      }}
    >
      {/* Header: search + skin tone */}
      <div className="flex items-center gap-2 border-b border-border p-2">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            data-testid="emoji-search"
            value={rawQuery}
            onChange={(e) => setRawQuery(e.target.value)}
            placeholder="Search emojis..."
            aria-label="Search emojis"
            className="h-8 pl-7 pr-7 text-sm"
            autoFocus
          />
          {rawQuery && (
            <button
              type="button"
              aria-label="Clear search"
              onClick={() => setRawQuery("")}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <Popover open={toneOpen} onOpenChange={setToneOpen}>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0 text-lg"
              data-testid="emoji-skin-tone-trigger"
              aria-label={`Skin tone: ${currentTone.label}`}
            >
              {applySkinTone("✋", skinTone)}
            </Button>
          </PopoverTrigger>
          <PopoverContent side="bottom" align="end" className="w-auto p-1.5" data-testid="emoji-skin-tone-popover">
            <div className="flex gap-1">
              {SKIN_TONES.map((tone) => (
                <button
                  key={tone.id}
                  type="button"
                  title={tone.label}
                  aria-label={`Skin tone ${tone.label}`}
                  data-tone={tone.id}
                  onClick={() => {
                    setSkinTone(tone.modifier);
                    setToneOpen(false);
                  }}
                  className={cn(
                    "flex h-8 w-8 items-center justify-center rounded text-lg hover:bg-accent",
                    tone.modifier === skinTone && "ring-2 ring-primary",
                  )}
                >
                  {applySkinTone("✋", tone.modifier)}
                </button>
              ))}
            </div>
          </PopoverContent>
        </Popover>
      </div>

      <div className="flex">
        {/* Category tabs (vertical sidebar) */}
        <div className="flex w-9 flex-col border-r border-border py-1" role="tablist" aria-label="Emoji categories">
          {EMOJI_CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              type="button"
              role="tab"
              aria-selected={activeCategory === cat.id}
              data-testid={`emoji-category-${cat.id}`}
              title={cat.label}
              aria-label={cat.label}
              onClick={() => scrollToCategory(cat.id)}
              className={cn(
                "flex h-8 w-full items-center justify-center text-base hover:bg-accent",
                activeCategory === cat.id && "bg-accent",
              )}
            >
              {cat.icon}
            </button>
          ))}
        </div>

        {/* Scrollable grid */}
        <div
          ref={gridRef}
          className="h-64 flex-1 overflow-y-auto p-1.5"
          style={{ contentVisibility: "auto" } as React.CSSProperties}
        >
          {query ? (
            // Search results
            searchResults.length > 0 ? (
              <div className="grid grid-cols-8 gap-0.5" data-testid="emoji-search-results">
                {searchResults.map((entry) => renderEmojiButton(entry, "search"))}
              </div>
            ) : (
              <div
                data-testid="emoji-empty-state"
                className="flex h-full items-center justify-center text-center text-xs text-muted-foreground"
              >
                No emojis found
              </div>
            )
          ) : (
            <>
              {/* Recent section */}
              {recentEmojis.length > 0 && (
                <div className="mb-2" data-testid="emoji-recent-section">
                  <p className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Recent
                  </p>
                  <div className="grid grid-cols-8 gap-0.5">
                    {recentEmojis.map((em, idx) => (
                      <button
                        key={`recent-${idx}-${em}`}
                        type="button"
                        data-emoji={em}
                        onClick={() => {
                          addRecent(em);
                          onSelect(em);
                        }}
                        className="flex h-8 w-8 items-center justify-center rounded text-xl hover:bg-accent"
                      >
                        {em}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Category sections */}
              {EMOJI_CATEGORIES.map((cat) => (
                <div
                  key={cat.id}
                  ref={(el) => {
                    sectionRefs.current[cat.id] = el;
                  }}
                  data-testid={`emoji-section-${cat.id}`}
                  className="mb-2"
                >
                  <p className="sticky top-0 z-10 mb-1 bg-popover px-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    {cat.label}
                  </p>
                  <div className="grid grid-cols-8 gap-0.5">
                    {EMOJI_BY_CATEGORY[cat.id].map((entry) => renderEmojiButton(entry, cat.id))}
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default EmojiPicker;
