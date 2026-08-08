/**
 * cpp-aware seeding glue for the creator-dashboard milestone domain
 * (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): creator-dashboard.spec.ts's
 * ddbPut/ddbDelete("app_single_table", {pk:USER#<email>, sk:MILESTONE#…|
 * MILESTONE_PREFS}) write/delete milestone rows into the Python DDB-Local :8001
 * table cpp never reads. cpp reads its OWN tlc_creator_milestones (moto :5005),
 * pk=USER#<sub>, same sk — so under E2E_USE_CPP the seeded milestones are
 * invisible and GET /ui/milestones + acknowledge + settings tests fail.
 *
 * FIX: when targeting cpp, route the app_single_table milestone put/delete to
 * seed_creator_milestone.py on .82, rewriting pk USER#<email> -> USER#<sub>
 * (resolved from loadSessions()). The default Python path is left byte-identical
 * (callers gate on usingCpp()). Only the milestone table is intercepted; other
 * ddbPut targets (billing / AnalyticsRollups) fall through untouched.
 */
import { runCppShim, usingCpp } from "./cpp-seed";
import { loadSessions } from "./session";

export { usingCpp };

const MILESTONE_TABLE = "app_single_table";

/** Extract the email from a USER#<email> pk and resolve the cpp SUB. */
function subFromPk(pk: string): string {
  const email = pk.startsWith("USER#") ? pk.slice(5) : pk;
  const sessions = loadSessions();
  return sessions[email]?.user_sub ?? email;
}

/** True when this ddbPut/ddbDelete target should route to cpp's milestone table. */
export function cppHandlesMilestoneTable(tableName: string): boolean {
  return usingCpp() && tableName === MILESTONE_TABLE;
}

/** Put ONE milestone (or PREFS) row into cpp's tlc_creator_milestones. */
export function cppMilestonePut(item: Record<string, unknown>): void {
  const pk = String(item.pk ?? "");
  runCppShim("seed_creator_milestone.py", {
    op: "put",
    user_sub: subFromPk(pk),
    item,
  });
}

/** Delete ONE milestone (or PREFS) row from cpp's tlc_creator_milestones. */
export function cppMilestoneDelete(key: Record<string, string>): void {
  const pk = String(key.pk ?? "");
  runCppShim("seed_creator_milestone.py", {
    op: "delete",
    user_sub: subFromPk(pk),
    sk: key.sk,
  });
}
