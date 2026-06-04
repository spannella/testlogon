import type { ReactNode } from "react";
import { toast as sonnerToast } from "sonner";

/**
 * Compatibility shim for the shadcn-style `useToast()` / `toast({...})` API,
 * implemented on top of `sonner` (the toast system mounted in main.tsx).
 *
 * Several pages were written against the shadcn `useToast` hook
 * (`const { toast } = useToast(); toast({ title, description, variant })`)
 * while the rest of the app uses sonner directly. This shim bridges the two
 * so those pages render without a missing-module import error.
 */

export interface ToastOptions {
  title?: ReactNode;
  description?: ReactNode;
  variant?: "default" | "destructive";
}

function emitToast({ title, description, variant }: ToastOptions = {}) {
  const message = (title ?? description ?? "") as string;
  const opts = title && description ? { description } : undefined;
  if (variant === "destructive") {
    return sonnerToast.error(message, opts);
  }
  return sonnerToast(message, opts);
}

export function useToast() {
  return {
    toast: emitToast,
    dismiss: (toastId?: string | number) => sonnerToast.dismiss(toastId),
  };
}

export const toast = emitToast;
