import { Link } from "react-router-dom";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import type { SyndicateFeedMember } from "@/api/types";

interface SyndicateMemberCardProps {
  member: SyndicateFeedMember;
}

export function SyndicateMemberCard({ member }: SyndicateMemberCardProps) {
  const isAdmin = member.role === "admin";
  const initials = (member.display_name || member.user_id || "?").slice(0, 2).toUpperCase();
  return (
    <Link
      to={`/profile/${member.user_id}`}
      className="flex items-center gap-3 rounded-lg border p-3 hover:bg-muted/50"
      data-testid="syndicate-member-card"
    >
      <Avatar className="h-12 w-12">
        <AvatarFallback>{initials}</AvatarFallback>
      </Avatar>
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium">{member.display_name || member.user_id}</div>
        <Badge
          variant={isAdmin ? "default" : "secondary"}
          className={isAdmin ? "bg-orange-500 hover:bg-orange-600" : ""}
        >
          {isAdmin ? "Admin" : "Member"}
        </Badge>
      </div>
    </Link>
  );
}

export default SyndicateMemberCard;
