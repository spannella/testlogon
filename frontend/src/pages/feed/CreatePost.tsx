import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { createPost } from "@/api/endpoints/newsfeed";

export function CreatePost() {
  const queryClient = useQueryClient();
  const [body, setBody] = useState("");

  const mutation = useMutation({
    mutationFn: () => createPost({ body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      setBody("");
      toast.success("Post published");
    },
    onError: () => {
      toast.error("Failed to create post");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim()) return;
    mutation.mutate();
  };

  return (
    <Card>
      <CardContent className="p-4">
        <form onSubmit={handleSubmit} className="space-y-3">
          <Textarea
            placeholder="What's on your mind?"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={3}
          />
          <div className="flex justify-end">
            <Button
              type="submit"
              size="sm"
              disabled={!body.trim() || mutation.isPending}
            >
              <Send className="mr-1 h-3.5 w-3.5" />
              {mutation.isPending ? "Posting..." : "Post"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
