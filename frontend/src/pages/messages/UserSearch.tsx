import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, User } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { searchUsers } from "@/api/endpoints/messaging";
import type { UserSearchResult } from "@/api/types";

interface UserSearchProps {
  onSelect: (user: UserSearchResult) => void;
  placeholder?: string;
  className?: string;
}

export function UserSearch({ onSelect, placeholder, className }: UserSearchProps) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);

  // Debounced query
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const debounce = useMemo(() => {
    return (value: string) => {
      const id = setTimeout(() => setDebouncedQuery(value), 300);
      return () => clearTimeout(id);
    };
  }, []);

  const handleChange = (value: string) => {
    setQuery(value);
    debounce(value);
    setOpen(value.trim().length > 0);
  };

  const { data: results } = useQuery({
    queryKey: ["user-search", debouncedQuery],
    queryFn: () => searchUsers(debouncedQuery, 10),
    enabled: debouncedQuery.trim().length > 0,
  });

  const users: UserSearchResult[] = results ?? [];

  const handleSelect = (user: UserSearchResult) => {
    onSelect(user);
    setQuery("");
    setDebouncedQuery("");
    setOpen(false);
  };

  return (
    <div className={cn("relative", className)}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder={placeholder ?? "Search users..."}
          value={query}
          onChange={(e) => handleChange(e.target.value)}
          onFocus={() => {
            if (query.trim()) setOpen(true);
          }}
          onBlur={() => {
            // Delay to allow click on result
            setTimeout(() => setOpen(false), 200);
          }}
          className="pl-9"
        />
      </div>

      {/* Dropdown results */}
      {open && users.length > 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-lg border border-border bg-popover shadow-lg">
          <ul className="max-h-48 overflow-y-auto py-1">
            {users.map((user) => (
              <li key={user.user_id}>
                <button
                  type="button"
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-accent"
                  onMouseDown={(e) => {
                    // Prevent input onBlur from closing dropdown before click registers
                    e.preventDefault();
                  }}
                  onClick={() => handleSelect(user)}
                >
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted">
                    <User className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{user.display_name}</p>
                    <p className="truncate text-xs text-muted-foreground">{user.user_id}</p>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* No results */}
      {open && debouncedQuery.trim().length > 0 && users.length === 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-lg border border-border bg-popover p-3 shadow-lg">
          <p className="text-center text-sm text-muted-foreground">No users found</p>
        </div>
      )}
    </div>
  );
}
