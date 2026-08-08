/**
 * cpp-aware seeding glue for the messaging-video-share domain (TRACK: seed).
 *
 * WHY: messaging-video-share.spec.ts hard-codes conversation ids (vs_dm_<ts>)
 * and references them in the shared-video message URL, so the real cpp
 * create-conversation API (which mints its OWN c_<...> id) cannot be used as-is.
 * A raw shim writing the spec's chosen id directly into cpp's
 * tlc_conversations + tlc_participants is the lower-churn fix.
 *
 * THE 403 THIS FIXES: the spec seeds conversation participants keyed by EMAIL
 * (ALICE_ID="e2e_alice@test.local"), but cpp's h_msg_video_share gate
 * (require_participant_active -> get_participant GetItem by {user_id: sub}) keys
 * by SUB. So an email-keyed participant row is invisible -> "Not a participant"
 * -> 403. cppSeedConversation MUST receive subs (map via resolveIdentityId in
 * the spec). Video + PM seeds already pass subs (ownerUserId=*_SUB()).
 *
 * Re-uses runCppShim/usingCpp from the shared module and re-exports the existing
 * cppSeedVideo/cppSeedPaymentMethod/cppDeleteVodVideo so the spec imports one
 * helper. The Python path is untouched (callers gate on usingCpp()).
 */
import { runCppShim, usingCpp, cppSeedVideo, cppSeedPaymentMethod } from "./cpp-seed";
import { cppDeleteVodVideo } from "./cpp-seed-video-vod";

export { usingCpp, cppSeedVideo, cppSeedPaymentMethod, cppDeleteVodVideo };

export interface CppSeedConversationOpts {
  conversationId: string;
  participantSubs: string[]; // cpp SUBS (map emails via resolveIdentityId first)
  type?: string;
  title?: string;
}

/**
 * Seed a messaging conversation + one active participant row per sub into cpp's
 * tlc_conversations + tlc_participants. Mirrors messaging-video-share.spec.ts
 * seedConversation() for the cpp store. All scalars land as strings (cpp's all-S
 * convention). Writes the caller-chosen conversation_id verbatim.
 */
export function cppSeedConversation(opts: CppSeedConversationOpts): void {
  runCppShim("seed_conversation.py", {
    conversation_id: opts.conversationId,
    participant_subs: opts.participantSubs,
    ...(opts.type ? { type: opts.type } : {}),
    ...(opts.title ? { title: opts.title } : {}),
  });
}
