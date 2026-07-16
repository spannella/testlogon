// Minimal ambient types for the Node built-ins used by the messaging-draft
// schema test (messagingDraftAnalyticsSchema.test.ts). @types/node is
// intentionally NOT a dependency of this DOM/browser project — pulling it in
// would change global signatures such as setTimeout/setInterval return types
// (number -> NodeJS.Timeout) and ripple across the codebase. These declarations
// are type-only and cover just what the test uses.
declare module "node:fs" {
  const fs: { readFileSync(path: string, encoding: string): string };
  export function readFileSync(path: string, encoding: string): string;
  export default fs;
}

declare module "node:path" {
  const path: { resolve(...segments: string[]): string };
  export function resolve(...segments: string[]): string;
  export default path;
}

declare const process: { cwd(): string };
