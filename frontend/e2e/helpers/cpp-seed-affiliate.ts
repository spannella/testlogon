/**
 * cpp-aware seeding glue for the affiliate-links domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): affiliate-links.spec.ts's
 * injectCatalogItem()/cleanupCatalogItem() write a shopping-catalog item
 * (PK/SK=ITEM#<id>) into the Python DDB-Local :8001 'shopping_catalog' table cpp
 * never reads. cpp's affiliate target lookup (afl_lookup_product) reads its OWN
 * tlc_catalog (moto :5005) — so under E2E_USE_CPP the item is invisible and
 * POST /ui/affiliates/links resolves target_name to the raw id, failing 1.1 and
 * cascading through the CRUD/click-tracking tests (aliceLinkId never set).
 *
 * FIX: when targeting cpp, invoke seed_affiliate_catalog_item.py on .82 so the
 * SAME item lands in cpp's tlc_catalog, with creator_id set to the cpp SUB
 * (resolved from loadSessions()). The default Python path is left byte-identical
 * (callers gate on usingCpp()).
 */
import { runCppShim, usingCpp } from "./cpp-seed";
import { loadSessions } from "./session";

export { usingCpp };

function resolveSub(emailOrSub: string): string {
  const sessions = loadSessions();
  return sessions[emailOrSub]?.user_sub ?? emailOrSub;
}

/** Seed ONE catalog item into cpp's tlc_catalog (PK/SK=ITEM#<id>). */
export function cppSeedAffiliateCatalogItem(
  ownerEmailOrSub: string,
  itemId: string,
  name: string,
): void {
  runCppShim("seed_affiliate_catalog_item.py", {
    op: "put",
    item_id: itemId,
    name,
    creator_sub: resolveSub(ownerEmailOrSub),
  });
}

/** Delete the seeded catalog item from cpp's tlc_catalog. */
export function cppCleanupAffiliateCatalogItem(itemId: string): void {
  try {
    runCppShim("seed_affiliate_catalog_item.py", { op: "delete", item_id: itemId });
  } catch {
    /* best-effort */
  }
}
