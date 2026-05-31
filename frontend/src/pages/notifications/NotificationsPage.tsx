import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Bell, CheckCheck, Heart, MessageSquare, AtSign, Users, Coins, AlertCircle } from "lucide-react";
import {
  getNotifications,
  getNotificationUnreadCount,
  markNotificationsRead,
  markAllNotificationsRead,
} from "@/api/endpoints/notifications";
import type { NotificationOut } from "@/api/types";

const TYPE_ICONS: Record<string, React.ReactNode> = {
  follow: <Users className="h-4 w-4 text-blue-500" />,
  like: <Heart className="h-4 w-4 text-red-500" />,
  comment: <MessageSquare className="h-4 w-4 text-green-500" />,
  mention: <AtSign className="h-4 w-4 text-purple-500" />,
  tip: <Coins className="h-4 w-4 text-amber-500" />,
  message: <MessageSquare className="h-4 w-4 text-sky-500" />,
  system: <AlertCircle className="h-4 w-4 text-gray-500" />,
};

function NotificationItem({
  notification,
  onMarkRead,
}: {
  notification: NotificationOut;
  onMarkRead: (id: string) => void;
}) {
  const icon = TYPE_ICONS[notification.notification_type] || <Bell className="h-4 w-4" />;
  const timeAgo = formatTimeAgo(notification.created_at);

  return (
    <div
      className={`flex items-start gap-3 rounded-lg border p-3 transition-colors ${
        notification.read ? "bg-background" : "bg-muted/50 border-primary/20"
      }`}
    >
      <div className="mt-0.5 shrink-0">{icon}</div>
      <div className="min-w-0 flex-1">
        <p className={`text-sm ${notification.read ? "text-muted-foreground" : "font-medium"}`}>
          {notification.title}
        </p>
        {notification.body && (
          <p className="mt-0.5 text-xs text-muted-foreground">{notification.body}</p>
        )}
        <div className="mt-1 flex items-center gap-2">
          <span className="text-xs text-muted-foreground">{timeAgo}</span>
          {notification.batch_count > 1 && (
            <Badge variant="secondary" className="text-xs">
              {notification.batch_count} events
            </Badge>
          )}
          <Badge variant="outline" className="text-xs capitalize">
            {notification.notification_type}
          </Badge>
        </div>
      </div>
      {!notification.read && (
        <Button
          variant="ghost"
          size="sm"
          className="shrink-0 text-xs"
          onClick={() => onMarkRead(notification.notification_id)}
        >
          Mark read
        </Button>
      )}
    </div>
  );
}

function formatTimeAgo(ts: number): string {
  const seconds = Math.floor(Date.now() / 1000) - ts;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function NotificationsPage() {
  const queryClient = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const { data, isLoading } = useQuery({
    queryKey: ["notifications-engine", cursor],
    queryFn: () => getNotifications({ limit: 30, cursor }),
  });

  const { data: unreadData } = useQuery({
    queryKey: ["notifications-engine-unread"],
    queryFn: () => getNotificationUnreadCount(),
  });

  const markReadMut = useMutation({
    mutationFn: (ids: string[]) => markNotificationsRead({ notification_ids: ids }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications-engine"] });
      queryClient.invalidateQueries({ queryKey: ["notifications-engine-unread"] });
    },
  });

  const markAllMut = useMutation({
    mutationFn: () => markAllNotificationsRead(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications-engine"] });
      queryClient.invalidateQueries({ queryKey: ["notifications-engine-unread"] });
    },
  });

  const notifications = data?.items ?? [];
  const unreadCount = unreadData?.count ?? data?.unread_count ?? 0;

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            <CardTitle>Notifications</CardTitle>
            {unreadCount > 0 && (
              <Badge variant="destructive">{unreadCount}</Badge>
            )}
          </div>
          {unreadCount > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => markAllMut.mutate()}
              disabled={markAllMut.isPending}
            >
              <CheckCheck className="mr-1 h-4 w-4" />
              Mark all read
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {isLoading && <p className="text-sm text-muted-foreground">Loading...</p>}

          {!isLoading && notifications.length === 0 && (
            <div className="py-8 text-center">
              <Bell className="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No notifications yet</p>
            </div>
          )}

          <div className="space-y-2">
            {notifications.map((n) => (
              <NotificationItem
                key={n.notification_id}
                notification={n}
                onMarkRead={(id) => markReadMut.mutate([id])}
              />
            ))}
          </div>

          {data?.next_cursor && (
            <div className="mt-4 text-center">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCursor(data.next_cursor ?? undefined)}
              >
                Load more
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
