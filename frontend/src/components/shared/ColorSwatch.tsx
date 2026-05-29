import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

interface ColorSwatchProps {
  /** CSS color value (hex, hsl, etc.) for the swatch background */
  color: string;
  /** Label for accessibility */
  label: string;
  /** Whether this swatch is currently selected */
  selected: boolean;
  /** Click handler */
  onClick: () => void;
  /** Optional additional class names */
  className?: string;
}

/**
 * Circular color button with aria-pressed state.
 * Shows a check icon when selected.
 */
export function ColorSwatch({ color, label, selected, onClick, className }: ColorSwatchProps) {
  return (
    <button
      type="button"
      aria-label={label}
      aria-pressed={selected}
      onClick={onClick}
      className={cn(
        "relative flex h-8 w-8 items-center justify-center rounded-full border-2 transition-all",
        "hover:scale-110 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
        selected ? "border-foreground ring-2 ring-ring ring-offset-2 ring-offset-background" : "border-transparent",
        className,
      )}
      style={{ backgroundColor: color }}
      data-testid={`color-swatch-${label.toLowerCase()}`}
    >
      {selected && (
        <Check
          className="h-4 w-4"
          style={{
            // Auto-contrast: white check on dark swatches, dark check on light ones
            color: "white",
            filter: "drop-shadow(0 0 1px rgba(0,0,0,0.5))",
          }}
        />
      )}
    </button>
  );
}
