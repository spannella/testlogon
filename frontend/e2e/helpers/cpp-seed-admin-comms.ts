/**
 * cpp-aware seeding glue for the admin email/SMS dashboards domain
 * (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): admin-email-sms-dashboards.spec's
 * seedDeliveryData() writes email_delivery / sms_delivery /
 * admin_messaging_templates rows into a Python DDB-Local :8001. The C++ backend
 * reads its OWN store — moto :5005 on .82, tables tlc_email_delivery /
 * tlc_sms_delivery / tlc_admin_messaging_templates — so under E2E_USE_CPP those
 * seeds are invisible and the stats / bounce / failure / template endpoints come
 * back empty.
 *
 * FIX: when targeting cpp, invoke seed_admin_email_sms.py on .82 so the SAME
 * canonical fixture lands in cpp's tlc_ tables (populating the ByStatus GSI on
 * put). The default Python path is left byte-identical (callers gate on
 * usingCpp()). These rows are admin-global, so no per-user SUB resolution is
 * needed.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

/** Seed the canonical email/SMS delivery + template fixture into cpp. */
export function cppSeedAdminComms(): void {
  runCppShim("seed_admin_email_sms.py", {});
}
