/**
 * Shared E2E data-cleanup helper.
 *
 * Cross-spec interference (a spec's leftover rows inflating another spec's
 * counts/lists) is the main reason specs pass in isolation but fail in a full
 * suite run. Specs should remove their own footprint in afterAll/afterEach by
 * calling cleanupDdb() with the table + key prefixes they created under.
 *
 * Implemented via a short python helper (sources .env.local for the DDB
 * endpoint + table-name env) and deletes by pk (and optional sk) prefix,
 * paginating to cover >1MB scans.
 */
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

export interface CleanupTarget {
  /** Logical table name (env-overridable name resolved server-side by default). */
  table: string;
  /** Delete items whose partition key starts with this string. */
  pkPrefix?: string;
  /** Optionally also require the sort key to start with this string. */
  skPrefix?: string;
  /** PK / SK attribute names if non-default. */
  pkName?: string;
  skName?: string;
}

/**
 * Delete all items in `table` whose pk (and optionally sk) start with the given
 * prefixes. Best-effort: never throws (cleanup must not fail a test run).
 */
export function cleanupDdb(targets: CleanupTarget | CleanupTarget[]): void {
  const list = Array.isArray(targets) ? targets : [targets];
  if (list.length === 0) return;
  const spec = JSON.stringify(list).replace(/"/g, '\\"');
  const py = [
    "import os, json, boto3",
    "from pathlib import Path",
    "for ln in Path(REPO_ROOT + '/.env.local').read_text().splitlines():",
    "    ln=ln.strip()",
    "    if ln and not ln.startswith('#') and '=' in ln:",
    "        k,v=ln.split('=',1); os.environ.setdefault(k.strip(), v.strip())",
    "ddb=boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')",
    `targets=json.loads(\\"${spec}\\")`,
    "for t in targets:",
    "    name=t['table']; pkn=t.get('pkName','pk'); skn=t.get('skName','sk')",
    "    tbl=ddb.Table(name)",
    "    lek=None; deleted=0",
    "    while True:",
    "        kw={} if lek is None else {'ExclusiveStartKey': lek}",
    "        try:",
    "            r=tbl.scan(**kw)",
    "        except Exception:",
    "            break",
    "        for it in r.get('Items', []):",
    "            pkv=str(it.get(pkn,'')); skv=str(it.get(skn,''))",
    "            if t.get('pkPrefix') and not pkv.startswith(t['pkPrefix']): continue",
    "            if t.get('skPrefix') and not skv.startswith(t['skPrefix']): continue",
    "            key={pkn: it.get(pkn)}",
    "            if skn in it: key[skn]=it.get(skn)",
    "            try: tbl.delete_item(Key=key); deleted+=1",
    "            except Exception: pass",
    "        lek=r.get('LastEvaluatedKey')",
    "        if not lek: break",
    "    print(f'cleaned {name} {deleted}')",
  ].join("\n");
  try {
    execSync(`python3 -c "${py}"`, { cwd: REPO_ROOT, timeout: 30_000 });
  } catch {
    // best-effort: never fail a test run on cleanup
  }
}
