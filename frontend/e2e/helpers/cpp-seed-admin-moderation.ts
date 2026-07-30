/**
 * cpp-aware seeding glue for admin-moderation.spec.ts (TRACK: seed).
 *
 * PROBLEM: the inline seedTicket() in the spec writes the moderation ticket into
 * the Python 'moderation_tickets' table + the offender post into
 * 'app_single_table' at :8001. The C++ backend reads its OWN moto on .82
 * (tlc_moderation_tickets keyed by ticket_id / tlc_newsfeed POST#/META). Under
 * E2E_USE_CPP those seeds never reach cpp so the list/detail/claim/decide tests
 * find nothing. This wrapper invokes the arg-driven shim on .82 so the correctly
 * shaped rows land in cpp's tables.
 *
 * Reuses the shared cpp-seed.ts runCppShim primitive (per-worker ssh
 * ControlMaster multiplexing). Default Python path is untouched: caller gates on
 * usingCpp().
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

const SHIM = "seed_moderation_ticket.py";

/** Seed ONE moderation ticket (+ offender feed post) into cpp's moto.
 *  offenderSub MUST be the cpp SUB (used as content author + offender id). */
export function cppSeedModerationTicket(opts: {
  ticketId: string;
  contentId: string;
  offenderSub: string;
  contentType?: string;
}): void {
  runCppShim(SHIM, {
    ticket_id: opts.ticketId,
    content_id: opts.contentId,
    offender_sub: opts.offenderSub,
    content_type: opts.contentType ?? "feed_post",
  });
}
