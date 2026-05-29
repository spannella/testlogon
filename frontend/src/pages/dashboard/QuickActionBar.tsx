import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { PenLine, Radio, CalendarClock } from "lucide-react";

export default function QuickActionBar() {
  const navigate = useNavigate();

  return (
    <div className="flex gap-2 flex-wrap">
      <Button
        variant="default"
        size="sm"
        onClick={() => navigate("/feed")}
        className="gap-2"
      >
        <PenLine className="h-4 w-4" />
        New Post
      </Button>
      <Button
        variant="secondary"
        size="sm"
        onClick={() => navigate("/broadcast")}
        className="gap-2"
      >
        <Radio className="h-4 w-4" />
        Go Live
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={() => navigate("/scheduler")}
        className="gap-2"
      >
        <CalendarClock className="h-4 w-4" />
        Schedule
      </Button>
    </div>
  );
}
