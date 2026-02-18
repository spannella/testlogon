export interface PasswordPolicyCheck {
  id: string;
  label: string;
  met: boolean;
}

export interface PasswordPolicyResult {
  checks: PasswordPolicyCheck[];
  score: number;
  isStrong: boolean;
}

const WEAK_SEQUENCES = ["1234", "password", "qwerty", "letmein", "admin"];

export function evaluateEncryptionPassword(password: string): PasswordPolicyResult {
  const checks: PasswordPolicyCheck[] = [
    { id: "length", label: "At least 12 characters", met: password.length >= 12 },
    { id: "upper", label: "Contains an uppercase letter", met: /[A-Z]/.test(password) },
    { id: "lower", label: "Contains a lowercase letter", met: /[a-z]/.test(password) },
    { id: "number", label: "Contains a number", met: /\d/.test(password) },
    { id: "symbol", label: "Contains a symbol", met: /[^A-Za-z0-9]/.test(password) },
    {
      id: "common",
      label: "Does not use common patterns",
      met: !WEAK_SEQUENCES.some((seq) => password.toLowerCase().includes(seq)),
    },
  ];

  const score = checks.filter((c) => c.met).length;
  const commonPatternCheck = checks.find((c) => c.id === "common");
  return {
    checks,
    score,
    isStrong: score >= 5 && !!commonPatternCheck?.met,
  };
}
