import * as React from "react";
import { cn } from "@/lib/utils";

interface OtpInputProps {
  length?: number;
  value: string;
  onChange: (value: string) => void;
  onComplete?: (value: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
  className?: string;
}

const OtpInput = React.forwardRef<HTMLDivElement, OtpInputProps>(
  ({ length = 6, value, onChange, onComplete, disabled, autoFocus, className }, ref) => {
    const inputRefs = React.useRef<(HTMLInputElement | null)[]>([]);

    const digits = value.split("").concat(Array(length).fill("")).slice(0, length);

    const focusInput = (index: number) => {
      const clamped = Math.max(0, Math.min(index, length - 1));
      inputRefs.current[clamped]?.focus();
    };

    const handleChange = (index: number, char: string) => {
      if (disabled) return;

      // Only allow digits
      const digit = char.replace(/\D/g, "").slice(-1);
      if (!digit && char !== "") return;

      const arr = digits.slice();
      arr[index] = digit;
      const next = arr.join("").slice(0, length);
      onChange(next);

      if (digit && index < length - 1) {
        focusInput(index + 1);
      }

      if (digit && next.length === length) {
        onComplete?.(next);
      }
    };

    const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
      if (e.key === "Backspace") {
        e.preventDefault();
        if (digits[index]) {
          handleChange(index, "");
        } else if (index > 0) {
          focusInput(index - 1);
          handleChange(index - 1, "");
        }
      } else if (e.key === "ArrowLeft" && index > 0) {
        e.preventDefault();
        focusInput(index - 1);
      } else if (e.key === "ArrowRight" && index < length - 1) {
        e.preventDefault();
        focusInput(index + 1);
      }
    };

    const handlePaste = (e: React.ClipboardEvent) => {
      e.preventDefault();
      const pasted = e.clipboardData.getData("text/plain").replace(/\D/g, "").slice(0, length);
      if (pasted) {
        onChange(pasted);
        focusInput(Math.min(pasted.length, length - 1));
        if (pasted.length === length) {
          onComplete?.(pasted);
        }
      }
    };

    React.useEffect(() => {
      if (autoFocus) {
        inputRefs.current[0]?.focus();
      }
    }, [autoFocus]);

    return (
      <div ref={ref} className={cn("flex items-center gap-2", className)}>
        {Array.from({ length }).map((_, i) => (
          <input
            key={i}
            ref={(el) => { inputRefs.current[i] = el; }}
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={1}
            value={digits[i] ?? ""}
            disabled={disabled}
            className={cn(
              "h-12 w-10 rounded-lg border border-input bg-transparent text-center text-lg font-semibold shadow-sm transition-all",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:border-primary",
              "disabled:cursor-not-allowed disabled:opacity-50",
              "placeholder:text-muted-foreground/30",
            )}
            placeholder="0"
            onChange={(e) => handleChange(i, e.target.value)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            onPaste={handlePaste}
            onFocus={(e) => e.target.select()}
          />
        ))}
      </div>
    );
  },
);
OtpInput.displayName = "OtpInput";

export { OtpInput };
