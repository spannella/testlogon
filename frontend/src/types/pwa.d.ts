export {};

declare global {
  /**
   * BeforeInstallPromptEvent -- fired by Chromium browsers when the app
   * meets PWA installability criteria. Not part of the standard DOM types.
   *
   * @see https://developer.mozilla.org/en-US/docs/Web/API/BeforeInstallPromptEvent
   */
  interface BeforeInstallPromptEvent extends Event {
    /**
     * Array of platform strings (e.g., ["web", "play"]) indicating which
     * platforms the browser can install to.
     */
    readonly platforms: string[];

    /**
     * Promise that resolves when the user responds to the install prompt.
     * `outcome` is "accepted" if they installed, "dismissed" if they declined.
     */
    readonly userChoice: Promise<{
      outcome: "accepted" | "dismissed";
      platform: string;
    }>;

    /**
     * Show the install prompt dialog. Can only be called once per
     * beforeinstallprompt event. Must be called in a user gesture context.
     */
    prompt(): Promise<void>;
  }

  interface WindowEventMap {
    /** Fired when Chrome determines the app is installable. */
    beforeinstallprompt: BeforeInstallPromptEvent;

    /** Fired after the user has installed the PWA. */
    appinstalled: Event;
  }
}
