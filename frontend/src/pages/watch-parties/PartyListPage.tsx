import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { listParties } from "@/api/endpoints/watchParties";
import CreatePartyDialog from "./CreatePartyDialog";
import { Tv, Users, Clock } from "lucide-react";

function statusColor(status: string) {
  switch (status) {
    case "waiting": return "secondary";
    case "playing": return "default";
    case "paused": return "outline";
    case "ended": return "destructive";
    default: return "secondary";
  }
}

export default function PartyListPage() {
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({
    queryKey: ["watch-parties"],
    queryFn: () => listParties(),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Tv className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Watch Parties</h1>
        </div>
        <CreatePartyDialog />
      </div>

      {isLoading && <p>Loading...</p>}

      {data && data.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No watch parties yet. Create one to get started!
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {data?.map((party) => (
          <Card key={party.party_id} className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={() => navigate(`/watch-parties/${party.party_id}`)}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg truncate">{party.title}</CardTitle>
                <Badge variant={statusColor(party.status)}>{party.status}</Badge>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground truncate">{party.video_title}</p>
              <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Users className="h-3 w-3" />
                  {party.participant_count}/{party.max_participants}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {new Date(party.created_at * 1000).toLocaleDateString()}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Invite: <code className="bg-muted px-1 rounded">{party.invite_code}</code>
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
