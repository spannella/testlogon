/**
 * Service Worker + Push Subscription helpers (PLATFORM-010).
 *
 * Call registerServiceWorker() on app mount.
 * Call subscribeToPush() when the user clicks "Enable Notifications".
 */

/**
 * Register the service worker. Returns the registration object or null.
 */
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) {
    console.warn("Service workers not supported");
    return null;
  }
  try {
    const registration = await navigator.serviceWorker.register("/sw.js", {
      scope: "/",
    });
    console.log("SW registered:", registration.scope);
    return registration;
  } catch (err) {
    console.error("SW registration failed:", err);
    return null;
  }
}

/**
 * Convert a URL-safe base64 string to a Uint8Array (for applicationServerKey).
 *
 * VAPID public keys are encoded as URL-safe base64 without padding.
 * PushManager.subscribe() requires a Uint8Array.
 */
export function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

/**
 * Subscribe the browser to push notifications using the server's VAPID key.
 *
 * Returns the PushSubscription JSON string to send to POST /ui/push/register.
 * Throws if permission denied or subscription fails.
 */
export async function subscribeToPush(
  vapidPublicKey: string,
): Promise<string> {
  const registration = await navigator.serviceWorker.ready;

  // Check for existing subscription
  const existing = await registration.pushManager.getSubscription();
  if (existing) {
    // Already subscribed -- return existing subscription
    return JSON.stringify(existing.toJSON());
  }

  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
  });

  return JSON.stringify(subscription.toJSON());
}

/**
 * Unsubscribe from push notifications (called on device revoke).
 */
export async function unsubscribeFromPush(): Promise<boolean> {
  if (!("serviceWorker" in navigator)) return false;
  try {
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      return await subscription.unsubscribe();
    }
  } catch (err) {
    console.error("Push unsubscribe failed:", err);
  }
  return false;
}
