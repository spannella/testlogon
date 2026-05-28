/* sw.js -- Web Push Service Worker (PLATFORM-010)
 *
 * Handles:
 * - push: Show native browser notification
 * - notificationclick: Focus/open app tab at the relevant URL
 *
 * Does NOT handle fetch caching or offline support.
 */

// Activate immediately on install (skip waiting for existing clients to close)
self.addEventListener("install", (event) => {
  self.skipWaiting();
});

// Claim all clients immediately on activate
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Handle incoming push notification
self.addEventListener("push", (event) => {
  if (!event.data) {
    // No payload -- show a generic notification
    event.waitUntil(
      self.registration.showNotification("New notification", {
        body: "You have a new notification",
        icon: "/favicon.svg",
        badge: "/favicon.svg",
      })
    );
    return;
  }

  let payload;
  try {
    payload = event.data.json();
  } catch (e) {
    // Fallback: treat as plain text
    payload = { title: "Notification", body: event.data.text() };
  }

  const title = payload.title || "Notification";
  const options = {
    body: payload.body || "",
    icon: payload.icon || "/favicon.svg",
    badge: payload.badge || "/favicon.svg",
    data: {
      url: payload.url || "/",
      alertId: payload.alert_id || "",
      alertType: payload.alert_type || "",
    },
    tag: payload.tag || payload.alert_type || "default",
    renotify: !!payload.tag,
    timestamp: payload.timestamp ? new Date(payload.timestamp * 1000).getTime() : Date.now(),
    silent: false,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// Handle notification click -- navigate to the relevant page
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const url = event.notification.data?.url || "/";
  const fullUrl = new URL(url, self.location.origin).href;

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        // Try to find an existing app tab to focus + navigate
        for (const client of clientList) {
          if (client.url.startsWith(self.location.origin) && "focus" in client) {
            return client.navigate(fullUrl).then(() => client.focus());
          }
        }
        // No existing tab -- open a new one
        return self.clients.openWindow(fullUrl);
      })
  );
});

// Handle notification close (analytics, optional)
self.addEventListener("notificationclose", (event) => {
  // Future: track notification dismissal rate
});
